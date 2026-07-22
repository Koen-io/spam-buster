"""Local web server: the dashboard UI and its JSON API.

Binds to 127.0.0.1 only — nothing is exposed to the network.
"""

import os
import re
import threading
import time

from flask import Flask, jsonify, request, send_from_directory

from . import (auth, config, database as db, detector, logutil, paths,
               updater, __version__)
from .engine import engine

log = logutil.get_logger("server")


def _slug(email):
    base = re.sub(r"[^a-z0-9]+", "", (email.split("@", 1)[0] or "acct").lower()) or "acct"
    cfg = config.load()
    existing = {a["id"] for a in cfg.get("accounts", [])}
    slug, i = base, 1
    while slug in existing:
        i += 1
        slug = f"{base}{i}"
    return slug


def _account_view(cfg):
    cid = cfg.get("azure_client_id")
    out = []
    for a in cfg.get("accounts", []):
        out.append({
            "id": a["id"], "email": a["email"],
            "enabled": a.get("enabled", True),
            "connected": bool(cid) and auth.has_token(cid, a["id"]),
        })
    return out


def create_app():
    app = Flask(__name__, static_folder=None)

    # ---------------------------------------------------- static UI
    @app.route("/")
    def index():
        return send_from_directory(paths.WEB_DIR, "index.html")

    @app.route("/<path:fname>")
    def static_files(fname):
        if os.path.exists(os.path.join(paths.WEB_DIR, fname)):
            return send_from_directory(paths.WEB_DIR, fname)
        return ("Not found", 404)

    # ---------------------------------------------------- state
    @app.route("/api/state")
    def api_state():
        cfg = config.load()
        suggestions = []
        for a in cfg.get("accounts", []):
            for s in (db.get_meta(f"suggestions:{a['id']}", []) or []):
                suggestions.append({**s, "account": a["email"]})
        suggestions.sort(key=lambda x: x.get("confidence", 0), reverse=True)
        return jsonify({
            "suggestions": suggestions[:8],
            "version": __version__,
            "first_run": cfg.get("first_run", True),
            "configured_client": bool(cfg.get("azure_client_id")),
            "detection": cfg["detection"],
            "updates": cfg["updates"],
            "accounts": _account_view(cfg),
            "stats": db.stats(),
            "engine": {
                "running": engine.status.get("running"),
                "paused": engine.paused,
                "scanning": engine.status.get("scanning"),
                "last_scan": engine.status.get("last_scan"),
                "last_error": engine.status.get("last_error"),
                "accounts": engine.status.get("accounts", {}),
            },
        })

    # ---------------------------------------------------- settings
    @app.route("/api/settings", methods=["POST"])
    def api_settings():
        patch = request.get_json(force=True) or {}
        allowed = {}
        if "azure_client_id" in patch:
            allowed["azure_client_id"] = patch["azure_client_id"].strip()
        if "detection" in patch:
            allowed["detection"] = patch["detection"]
        if "updates" in patch:
            allowed["updates"] = {k: patch["updates"][k]
                                  for k in ("repo", "channel", "auto_check",
                                            "check_interval_hours")
                                  if k in patch["updates"]}
        if "first_run" in patch:
            allowed["first_run"] = patch["first_run"]
        cfg = config.update(allowed)
        engine.wake()
        return jsonify({"ok": True, "detection": cfg["detection"]})

    # ---------------------------------------------------- accounts
    @app.route("/api/account/add", methods=["POST"])
    def api_account_add():
        data = request.get_json(force=True) or {}
        email = (data.get("email") or "").strip().lower()
        if "@" not in email:
            return jsonify({"ok": False, "error": "Enter a valid email address."}), 400
        cfg = config.load()
        if any(a["email"] == email for a in cfg["accounts"]):
            return jsonify({"ok": False, "error": "Account already added."}), 400
        acct = {"id": _slug(email), "email": email, "enabled": True}
        cfg["accounts"].append(acct)
        config.save(cfg)
        return jsonify({"ok": True, "account": acct})

    @app.route("/api/account/remove", methods=["POST"])
    def api_account_remove():
        data = request.get_json(force=True) or {}
        aid = data.get("id")
        cfg = config.load()
        cfg["accounts"] = [a for a in cfg["accounts"] if a["id"] != aid]
        config.save(cfg)
        auth.sign_out(aid)
        return jsonify({"ok": True})

    @app.route("/api/account/toggle", methods=["POST"])
    def api_account_toggle():
        data = request.get_json(force=True) or {}
        aid, enabled = data.get("id"), bool(data.get("enabled"))
        cfg = config.load()
        for a in cfg["accounts"]:
            if a["id"] == aid:
                a["enabled"] = enabled
        config.save(cfg)
        return jsonify({"ok": True})

    @app.route("/api/account/connect", methods=["POST"])
    def api_account_connect():
        data = request.get_json(force=True) or {}
        aid = data.get("id")
        cfg = config.load()
        cid = cfg.get("azure_client_id")
        if not cid:
            return jsonify({"ok": False,
                            "error": "Add your Microsoft app ID in Settings first."}), 400
        info = auth.device_flow.start(cid, aid)
        return jsonify({"ok": info.get("status") != "error", **info})

    @app.route("/api/account/connect/status")
    def api_account_connect_status():
        aid = request.args.get("id")
        info = auth.device_flow.status(aid)
        if info.get("status") == "connected":
            config.update({"first_run": False})
            engine.wake()
        return jsonify(info)

    @app.route("/api/account/signout", methods=["POST"])
    def api_account_signout():
        data = request.get_json(force=True) or {}
        auth.sign_out(data.get("id"))
        return jsonify({"ok": True})

    # ---------------------------------------------------- reports
    @app.route("/api/reports")
    def api_reports():
        cfg = config.load()
        min_obs = cfg["detection"].get("min_observations", 3)
        suggestions = []
        for a in cfg["accounts"]:
            for s in (db.get_meta(f"suggestions:{a['id']}", []) or []):
                suggestions.append({**s, "account": a["email"]})
        suggestions.sort(key=lambda x: x.get("confidence", 0), reverse=True)
        return jsonify({
            "rules": detector.rules_summary(min_observations=min_obs),
            "events": db.recent_events(60),
            "suggestions": suggestions[:50],
            "stats": db.stats(),
        })

    # ---------------------------------------------------- quarantine
    @app.route("/api/quarantine")
    def api_quarantine():
        return jsonify({
            "active": db.list_quarantine("quarantined"),
            "restored": db.list_quarantine("restored", limit=100),
        })

    @app.route("/api/quarantine/restore", methods=["POST"])
    def api_quarantine_restore():
        data = request.get_json(force=True) or {}
        ok, msg = engine.restore(int(data.get("id")))
        return jsonify({"ok": ok, "message": msg})

    # ---------------------------------------------------- engine controls
    @app.route("/api/scan", methods=["POST"])
    def api_scan():
        engine.wake()
        return jsonify({"ok": True})

    @app.route("/api/pause", methods=["POST"])
    def api_pause():
        data = request.get_json(force=True) or {}
        engine.set_paused(bool(data.get("paused")))
        return jsonify({"ok": True, "paused": engine.paused})

    @app.route("/api/logs")
    def api_logs():
        return jsonify({"log": logutil.tail(300)})

    # ---------------------------------------------------- updates
    @app.route("/api/updates/check", methods=["POST", "GET"])
    def api_updates_check():
        return jsonify(updater.check_for_updates())

    @app.route("/api/updates/apply", methods=["POST"])
    def api_updates_apply():
        result = updater.apply_update()
        if result.get("status") == "ok":
            threading.Thread(target=_delayed_restart, daemon=True).start()
        return jsonify(result)

    return app


def _delayed_restart():
    time.sleep(1.5)
    log.info("Restarting after update…")
    # launchd (KeepAlive) relaunches us; a clean exit is enough.
    os._exit(0)


def run(host=None, port=None):
    cfg = config.load()
    host = host or cfg["server"]["host"]
    port = port or cfg["server"]["port"]
    app = create_app()
    log.info("Dashboard on http://%s:%s", host, port)
    app.run(host=host, port=port, threaded=True, use_reloader=False)
