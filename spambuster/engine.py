"""The background engine: scan Junk folders, learn from your deletions, and
(optionally) auto-delete high-confidence spam into a recoverable quarantine.

Learning signal
---------------
Between two scans, if a message that was UNREAD vanishes from the Junk folder,
you deleted it unread -> a confirmed spam example. Messages you read first are
treated as neutral (you engaged with them), so we never learn from those.
"""

import threading
import time
import traceback

from . import auth, config, database as db, detector, graph, logutil, protection

log = logutil.get_logger("engine")

# Set by the menu-bar app to surface native notifications.
ALERT_CALLBACK = None


def emit_alert(title, message):
    cb = ALERT_CALLBACK
    if cb:
        try:
            cb(title, message)
        except Exception:
            pass


class Engine:
    def __init__(self):
        self._thread = None
        self._stop = threading.Event()
        self._wake = threading.Event()
        self.paused = False
        self.status = {
            "running": False,
            "last_scan": None,
            "last_error": None,
            "accounts": {},   # account_id -> {connected, junk_count, error}
            "scanning": False,
        }
        self._lock = threading.Lock()

    # -------------------------------------------------- lifecycle
    def start(self):
        if self._thread and self._thread.is_alive():
            return
        try:
            from . import model
            n = model.backfill()
            if n:
                log.info("Backfilled smart model from %d past examples", n)
        except Exception as e:  # noqa
            log.debug("model backfill skipped: %s", e)
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        self.status["running"] = True
        log.info("Engine started")

    def stop(self):
        self._stop.set()
        self._wake.set()
        self.status["running"] = False

    def wake(self):
        """Trigger an immediate scan."""
        self._wake.set()

    def set_paused(self, paused):
        self.paused = bool(paused)
        db.set_meta("engine_paused", self.paused)
        if not paused:
            self.wake()

    def _loop(self):
        self.paused = bool(db.get_meta("engine_paused", False))
        while not self._stop.is_set():
            cfg = config.load()
            interval = cfg["detection"].get("poll_interval_seconds", 120)
            if not self.paused:
                try:
                    self.scan_all(cfg)
                except Exception as e:  # noqa
                    self.status["last_error"] = str(e)
                    log.error("scan_all crashed: %s\n%s", e, traceback.format_exc())
            self._wake.wait(timeout=interval)
            self._wake.clear()

    # -------------------------------------------------- scanning
    def scan_all(self, cfg=None):
        cfg = cfg or config.load()
        client_id = cfg.get("azure_client_id")
        self.status["scanning"] = True
        results = {}
        try:
            for acct in cfg.get("accounts", []):
                if not acct.get("enabled", True):
                    continue
                results[acct["id"]] = self._scan_account(cfg, client_id, acct)
            # Housekeeping: retire old quarantine entries from the recovery list.
            try:
                db.purge_quarantine_older(cfg.get("quarantine_retention_days", 30))
            except Exception:
                pass
        finally:
            self.status["scanning"] = False
            self.status["last_scan"] = time.time()
            self.status["accounts"] = results
        return results

    def _scan_account(self, cfg, client_id, acct):
        acct_id = acct["id"]
        info = {"connected": False, "junk_count": 0, "auto_deleted": 0,
                "learned": 0, "error": None}
        token = auth.get_token(client_id, acct_id)
        if not token:
            info["error"] = "not signed in"
            return info
        info["connected"] = True

        folders = acct.get("folders") or [{"id": "junkemail", "name": "Junk"}]
        current = []
        for f in folders:
            fid = f.get("id") or "junkemail"
            try:
                current.extend(graph.list_folder_messages(token, fid, top=100))
            except Exception as e:  # noqa
                info["error"] = str(e)
                log.warning("list folder %s failed for %s: %s", fid, acct_id, e)
        # de-duplicate (a message lives in one folder, but be safe)
        seen_ids_now = set()
        deduped = []
        for m in current:
            if m["graph_id"] in seen_ids_now:
                continue
            seen_ids_now.add(m["graph_id"])
            deduped.append(m)
        current = deduped

        info["junk_count"] = len(current)
        current_by_id = {m["graph_id"]: m for m in current}
        seen = db.get_seen_ids(acct_id)   # {graph_id: is_read}

        # 1) Detect disappearances = things you removed since last scan.
        for gid, was_read in seen.items():
            if gid in current_by_id:
                continue
            prev = db.get_seen(acct_id, gid)
            db.delete_seen(acct_id, gid)
            if prev and not was_read:
                # Deleted while unread -> confirmed spam.
                detector.learn(acct_id, prev, label="spam", source="user",
                               kind="deleted_unread")
                info["learned"] += 1
                log.info("learned spam from deleted-unread: %s | %s",
                         prev.get("sender"), (prev.get("subject") or "")[:60])

        # 2) Handle messages currently in the monitored folders.
        mode = acct.get("mode") or cfg["detection"].get("mode", "observe")
        threshold = cfg["detection"].get("confidence_threshold", 95)
        min_obs = cfg["detection"].get("min_observations", 3)
        suggestions = []

        deep = cfg["detection"].get("deep_scan", True)
        for m in current:
            gid = m["graph_id"]
            is_new = gid not in seen
            db.upsert_seen(acct_id, m)

            prob, reasons, decisive = detector.score(m)

            # Deep mailbox-side analysis (auth / phishing / trackers / newsletter).
            if deep:
                analysis = self._protect(token, acct_id, m, is_new)
                if analysis:
                    prob, reasons, decisive = self._apply_protection(
                        cfg, analysis, prob, reasons, decisive)

            conf = round(prob * 100)

            # Your blocklist always deletes, in any mode.
            blocked = (db.list_has("block_sender", m["sender"])
                       or db.list_has("block_domain", m["sender_domain"]))

            would_delete = (conf >= threshold and decisive)
            if would_delete and not blocked:
                suggestions.append({
                    "graph_id": gid, "sender": m["sender"],
                    "subject": m["subject"], "confidence": conf,
                    "reasons": reasons,
                })

            if is_new and (blocked or (mode == "auto" and would_delete)):
                if self._auto_delete(token, acct_id, m, conf, reasons):
                    info["auto_deleted"] += 1

        db.set_meta(f"suggestions:{acct_id}", suggestions[:100])
        return info

    def _protect(self, token, acct_id, m, is_new):
        """Return analysis for a message, fetching+storing it once when new."""
        gid = m["graph_id"]
        if not db.has_analysis(acct_id, gid):
            try:
                full = graph.get_message_full(token, gid)
            except Exception as e:  # noqa
                log.debug("get_message_full failed: %s", e)
                return db.get_analysis(acct_id, gid)
            if not full:
                return None
            try:
                a = protection.analyze(full)
                db.save_analysis(acct_id, m, a)
            except Exception as e:  # noqa
                log.warning("protection.analyze failed: %s", e)
                return None
        return db.get_analysis(acct_id, gid)

    def _apply_protection(self, cfg, a, prob, reasons, decisive):
        """Fold auth/phishing verdicts into the spam decision."""
        det = cfg["detection"]
        extra = []
        if det.get("auth_as_spam", True) and a.get("spoofing"):
            prob = max(prob, 0.90)
            extra.append("Failed sender authentication (SPF/DKIM/DMARC) — likely spoofed")
        if det.get("phishing_scan", True) and a.get("is_phishing"):
            score = (a.get("phishing_score") or 0) / 100.0
            prob = max(prob, min(0.99, 0.80 + score * 0.19))
            if (a.get("phishing_score") or 0) >= 75:
                decisive = True
            try:
                import json
                pr = json.loads(a.get("phishing_reasons") or "[]")
            except Exception:
                pr = []
            extra.extend(pr[:2])
        if extra:
            reasons = extra + [r for r in reasons if r not in extra]
        return prob, reasons, decisive

    def _auto_delete(self, token, acct_id, m, conf, reasons):
        try:
            new_id = graph.soft_delete(token, m["graph_id"])
        except Exception as e:  # noqa
            log.warning("auto-delete move failed: %s", e)
            return False
        item = dict(m)
        item.update({"account_id": acct_id, "graph_id": new_id or m["graph_id"],
                     "confidence": conf, "reasons": reasons})
        db.add_quarantine(item)
        db.delete_seen(acct_id, m["graph_id"])  # so it isn't seen as a user deletion
        db.add_event(acct_id, kind="auto_deleted", label="spam", source="engine",
                     sender=m["sender"], sender_domain=m["sender_domain"],
                     subject=m["subject"], confidence=conf)
        log.info("AUTO-DELETED (%d%%): %s | %s", conf, m["sender"],
                 (m["subject"] or "")[:60])
        is_phish = any("phish" in r.lower() or "spoof" in r.lower() for r in (reasons or []))
        emit_alert("Threat removed" if is_phish else "Spam removed",
                   f"{m.get('sender','')} — {(m.get('subject') or '')[:50]}")
        return True

    # -------------------------------------------------- user actions
    def restore(self, qid):
        """Undo an auto-deletion: move it back to the Inbox and mark it not-spam."""
        item = db.get_quarantine(qid)
        if not item:
            return False, "not found"
        cfg = config.load()
        token = auth.get_token(cfg.get("azure_client_id"), item["account_id"])
        if not token:
            return False, "account not signed in"
        try:
            new_id = graph.restore_to_inbox(token, item["graph_id"])
        except Exception as e:  # noqa
            return False, str(e)
        db.set_quarantine_status(qid, "restored", new_graph_id=new_id)
        # Teach the brain this was a mistake.
        detector.learn(item["account_id"], {
            "sender": item["sender"], "sender_domain": item["sender_domain"],
            "sender_name": item.get("sender_name"), "subject": item["subject"],
        }, label="ham", source="user", kind="marked_not_spam")
        log.info("restored + learned ham: %s", item.get("sender"))
        return True, "restored"

    def mark_not_spam(self, qid):
        """Alias kept for clarity; same as restore."""
        return self.restore(qid)

    # -------------------------------------------------- accounts / folders
    def _token_for(self, account_id):
        cfg = config.load()
        return auth.get_token(cfg.get("azure_client_id"), account_id)

    def list_account_folders(self, account_id):
        token = self._token_for(account_id)
        if not token:
            return None, "account not signed in"
        try:
            return graph.list_folders(token), None
        except Exception as e:  # noqa
            return None, str(e)

    def empty_quarantine(self):
        return db.empty_quarantine()

    # -------------------------------------------------- newsletters

    def delete_newsletter(self, account_id, graph_id, reason="Newsletter — removed"):
        token = self._token_for(account_id)
        if not token:
            return False, "account not signed in"
        seen = db.get_seen(account_id, graph_id) or {"graph_id": graph_id}
        try:
            new_id = graph.soft_delete(token, graph_id)
        except Exception as e:  # noqa
            return False, str(e)
        item = {"account_id": account_id, "graph_id": new_id or graph_id,
                "sender": seen.get("sender"), "sender_domain": seen.get("sender_domain"),
                "sender_name": seen.get("sender_name"), "subject": seen.get("subject"),
                "received": seen.get("received"), "confidence": None, "reasons": [reason]}
        db.add_quarantine(item)
        db.delete_seen(account_id, graph_id)
        db.add_event(account_id, kind="auto_deleted", label="spam", source="user",
                     sender=seen.get("sender"), subject=seen.get("subject"))
        return True, "deleted"

    def bulk_delete_newsletters(self):
        deleted = 0
        for n in db.list_newsletters(limit=500):
            ok, _ = self.delete_newsletter(n["account_id"], n["graph_id"])
            if ok:
                deleted += 1
        return deleted

    def unsubscribe(self, account_id, graph_id):
        """RFC-8058 one-click unsubscribe (HTTP POST) when the sender supports it."""
        a = db.get_analysis(account_id, graph_id)
        if not a:
            return False, "no unsubscribe data"
        url = a.get("unsub_oneclick")
        if url:
            try:
                import requests
                r = requests.post(url, data="List-Unsubscribe=One-Click",
                                  headers={"Content-Type": "application/x-www-form-urlencoded"},
                                  timeout=20)
                if r.status_code < 400:
                    return True, "unsubscribed"
                return False, f"server returned {r.status_code}"
            except Exception as e:  # noqa
                return False, str(e)
        http = []
        try:
            import json
            http = json.loads(a.get("unsub_http") or "[]")
        except Exception:
            pass
        if http:
            return True, {"open_url": http[0]}   # let the user finish in a browser
        return False, "no one-click unsubscribe available"


engine = Engine()
