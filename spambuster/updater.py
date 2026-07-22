"""Self-update via a Git repository.

The app root is a git checkout of the Spam Buster repo. "Check for updates"
fetches the configured branch and compares commits; "Update now" fast-forwards
to the latest and re-installs dependencies if they changed.
"""

import datetime
import os
import subprocess

from . import config, logutil, paths

log = logutil.get_logger("updater")


def current_version():
    try:
        with open(os.path.join(paths.APP_ROOT, "VERSION"), encoding="utf-8") as f:
            return f.read().strip()
    except Exception:
        return "0.0.0"


def _git(*args, capture=True):
    return subprocess.run(
        ["git", "-C", paths.APP_ROOT, *args],
        capture_output=capture, text=True, timeout=120,
    )


def is_git_checkout():
    return os.path.isdir(os.path.join(paths.APP_ROOT, ".git"))


def _now_iso():
    return datetime.datetime.now().astimezone().isoformat(timespec="seconds")


def check_for_updates():
    cfg = config.load()
    repo = cfg["updates"].get("repo", "")
    channel = cfg["updates"].get("channel", "main")
    checked = _now_iso()

    if not is_git_checkout() or not repo:
        result = {"status": "not_configured", "available": False,
                  "current": current_version(),
                  "message": "Update source not set up yet."}
        config.update({"updates": {"last_checked": checked,
                                   "last_result": result["message"]}})
        return {**result, "last_checked": checked}

    try:
        # Fetch straight from the configured URL — never rewrite 'origin',
        # so local development (git push via SSH) keeps working.
        fetch = _git("fetch", repo, channel)
        if fetch.returncode != 0:
            raise RuntimeError(fetch.stderr.strip() or "git fetch failed")
        local = _git("rev-parse", "HEAD").stdout.strip()
        remote = _git("rev-parse", "FETCH_HEAD").stdout.strip()
        available = bool(local and remote and local != remote)
        message = "Update available." if available else "You’re up to date."
        result = {"status": "ok", "available": available,
                  "current": current_version(),
                  "local": local[:8], "remote": remote[:8], "message": message}
    except Exception as e:  # noqa
        log.warning("update check failed: %s", e)
        result = {"status": "error", "available": False,
                  "current": current_version(),
                  "message": f"Check failed: {e}"}

    config.update({"updates": {"last_checked": checked,
                               "last_result": result["message"]}})
    return {**result, "last_checked": checked}


def apply_update():
    cfg = config.load()
    channel = cfg["updates"].get("channel", "main")
    if not is_git_checkout():
        return {"status": "error", "message": "Not a git checkout — cannot update."}
    try:
        before_req = _read(os.path.join(paths.APP_ROOT, "requirements.txt"))
        cfg2 = config.load()
        repo = cfg2["updates"].get("repo", "")
        _git("fetch", repo, channel)
        reset = _git("reset", "--hard", "FETCH_HEAD")
        if reset.returncode != 0:
            raise RuntimeError(reset.stderr.strip() or "git reset failed")
        after_req = _read(os.path.join(paths.APP_ROOT, "requirements.txt"))
        deps_changed = before_req != after_req
        if deps_changed:
            _pip_install()
        config.update({"updates": {"last_checked": _now_iso(),
                                   "last_result": f"Updated to {current_version()}."}})
        return {"status": "ok", "version": current_version(),
                "deps_changed": deps_changed,
                "message": f"Updated to {current_version()}. Restarting…"}
    except Exception as e:  # noqa
        log.error("apply_update failed: %s", e)
        return {"status": "error", "message": str(e)}


def _read(path):
    try:
        with open(path, encoding="utf-8") as f:
            return f.read()
    except Exception:
        return ""


def _pip_install():
    py = os.path.join(paths.APP_ROOT, ".venv", "bin", "python")
    if not os.path.exists(py):
        py = "python3"
    subprocess.run([py, "-m", "pip", "install", "-r",
                    os.path.join(paths.APP_ROOT, "requirements.txt")],
                   capture_output=True, text=True, timeout=300)
