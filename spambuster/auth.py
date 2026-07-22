"""Microsoft sign-in via MSAL device-code flow.

No passwords are ever handled or stored. The user signs in once per account in
a browser; we cache the resulting OAuth tokens (encrypted-at-rest by file perms)
and refresh them silently forever after.
"""

import os
import threading

import msal

from . import paths

SCOPES = ["Mail.ReadWrite"]
AUTHORITY = "https://login.microsoftonline.com/consumers"  # personal Microsoft accounts


def _cache_path(account_id):
    return os.path.join(paths.TOKEN_DIR, f"{account_id}.bin")


def _load_cache(account_id):
    cache = msal.SerializableTokenCache()
    p = _cache_path(account_id)
    if os.path.exists(p):
        try:
            with open(p, "r", encoding="utf-8") as f:
                cache.deserialize(f.read())
        except Exception:
            pass
    return cache


def _save_cache(account_id, cache):
    if cache.has_state_changed:
        paths.ensure_dirs()
        p = _cache_path(account_id)
        with open(p, "w", encoding="utf-8") as f:
            f.write(cache.serialize())
        try:
            os.chmod(p, 0o600)
        except Exception:
            pass


def _app(client_id, account_id, cache):
    return msal.PublicClientApplication(
        client_id, authority=AUTHORITY, token_cache=cache
    )


def has_token(client_id, account_id):
    return get_token(client_id, account_id) is not None


def get_token(client_id, account_id):
    """Return a valid access token silently, or None if sign-in is required."""
    if not client_id:
        return None
    cache = _load_cache(account_id)
    app = _app(client_id, account_id, cache)
    accounts = app.get_accounts()
    if not accounts:
        return None
    result = app.acquire_token_silent(SCOPES, account=accounts[0])
    _save_cache(account_id, cache)
    if result and "access_token" in result:
        return result["access_token"]
    return None


def sign_out(account_id):
    p = _cache_path(account_id)
    try:
        if os.path.exists(p):
            os.remove(p)
    except Exception:
        pass


class DeviceFlowManager:
    """Runs device-code sign-ins in background threads and tracks their status."""

    def __init__(self):
        self._flows = {}   # account_id -> {message, user_code, verification_uri, status}
        self._lock = threading.Lock()

    def start(self, client_id, account_id):
        with self._lock:
            existing = self._flows.get(account_id)
            if existing and existing.get("status") == "pending":
                return existing

        cache = _load_cache(account_id)
        app = _app(client_id, account_id, cache)
        flow = app.initiate_device_flow(scopes=SCOPES)
        if "user_code" not in flow:
            info = {"status": "error",
                    "error": flow.get("error_description", "Could not start sign-in.")}
            with self._lock:
                self._flows[account_id] = info
            return info

        info = {
            "status": "pending",
            "user_code": flow["user_code"],
            "verification_uri": flow.get("verification_uri", "https://microsoft.com/devicelogin"),
            "message": flow.get("message", ""),
        }
        with self._lock:
            self._flows[account_id] = info

        def _worker():
            try:
                result = app.acquire_token_by_device_flow(flow)  # blocks until done/expired
            except Exception as e:  # noqa
                with self._lock:
                    self._flows[account_id] = {"status": "error", "error": str(e)}
                return
            if result and "access_token" in result:
                _save_cache(account_id, cache)
                with self._lock:
                    self._flows[account_id] = {"status": "connected"}
            else:
                with self._lock:
                    self._flows[account_id] = {
                        "status": "error",
                        "error": (result or {}).get("error_description", "Sign-in failed."),
                    }

        threading.Thread(target=_worker, daemon=True).start()
        return info

    def status(self, account_id):
        with self._lock:
            return dict(self._flows.get(account_id, {"status": "idle"}))


device_flow = DeviceFlowManager()
