"""Configuration: load, save, defaults, and safe merging.

Config is a single JSON file. It never stores mail credentials — Microsoft
sign-in produces OAuth tokens which are cached separately (see auth.py).
"""

import json
import os
import threading

from . import paths

_lock = threading.RLock()

DEFAULT_CONFIG = {
    # Azure app registration (public client) used for Microsoft sign-in.
    # The user pastes this in during onboarding; see README.
    "azure_client_id": "",

    # Mail accounts to watch. Each is a Hotmail/Outlook.com address.
    "accounts": [
        # {"id": "koen", "email": "koenschelvis@hotmail.com", "enabled": True}
    ],

    "detection": {
        # observe  -> learn only, delete nothing (default, safe)
        # suggest  -> build a suggested-spam list, never auto-delete
        # auto     -> auto-delete high-confidence spam into quarantine
        "mode": "observe",
        "confidence_threshold": 95,   # percent; auto-delete only above this
        "min_observations": 3,        # min confirmations before a sender/domain can auto-delete
        "poll_interval_seconds": 120,  # how often to scan the Junk folders
        "deep_scan": True,            # fetch headers+body for auth/phishing/tracker analysis
        "auth_as_spam": True,         # treat DMARC/SPF-failing (spoofed) mail as spam
        "phishing_scan": True,        # analyze links for phishing
    },

    "quarantine_retention_days": 30,   # keep deleted messages recoverable this long

    "updates": {
        "repo": "",                    # e.g. https://github.com/<you>/spam-buster.git
        "channel": "main",
        "auto_check": True,
        "check_interval_hours": 24,
        "last_checked": None,          # ISO timestamp of last update check
        "last_result": None,           # human-readable summary of last check
    },

    "server": {
        "host": "127.0.0.1",
        "port": 7676,
    },

    "language": "en",   # en | nl

    "first_run": True,
}


def _deep_merge(base, override):
    """Return base with override applied, recursively, without losing new default keys."""
    out = dict(base)
    for k, v in (override or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def load():
    with _lock:
        paths.ensure_dirs()
        if not os.path.exists(paths.CONFIG_PATH):
            save(DEFAULT_CONFIG)
            return json.loads(json.dumps(DEFAULT_CONFIG))
        try:
            with open(paths.CONFIG_PATH, "r", encoding="utf-8") as f:
                user_cfg = json.load(f)
        except Exception:
            user_cfg = {}
        # Merge onto defaults so upgrades pick up new keys.
        return _deep_merge(DEFAULT_CONFIG, user_cfg)


def save(cfg):
    with _lock:
        paths.ensure_dirs()
        tmp = paths.CONFIG_PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
        os.replace(tmp, paths.CONFIG_PATH)
        try:
            os.chmod(paths.CONFIG_PATH, 0o600)
        except Exception:
            pass
    return cfg


def update(patch):
    """Deep-merge a partial dict into the stored config and persist it."""
    with _lock:
        cfg = load()
        cfg = _deep_merge(cfg, patch)
        save(cfg)
        return cfg
