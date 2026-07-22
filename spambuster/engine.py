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

from . import auth, config, database as db, detector, graph, logutil

log = logutil.get_logger("engine")


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

        try:
            current = graph.list_junk(token, top=100)
        except Exception as e:  # noqa
            info["error"] = str(e)
            log.warning("list_junk failed for %s: %s", acct_id, e)
            return info

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

        # 2) Handle messages currently in Junk.
        mode = cfg["detection"].get("mode", "observe")
        threshold = cfg["detection"].get("confidence_threshold", 95)
        min_obs = cfg["detection"].get("min_observations", 3)
        suggestions = []

        for m in current:
            gid = m["graph_id"]
            is_new = gid not in seen
            db.upsert_seen(acct_id, m)

            prob, reasons, decisive = detector.score(m)
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


engine = Engine()
