"""Central place for all on-disk locations Spam Buster uses.

Everything lives under ~/Library/Application Support/SpamBuster so the app is
fully portable: install on any Mac and it creates its own home on first run.
"""

import os

APP_SUPPORT = os.path.expanduser("~/Library/Application Support/SpamBuster")
LOG_DIR = os.path.join(APP_SUPPORT, "logs")
TOKEN_DIR = os.path.join(APP_SUPPORT, "tokens")

CONFIG_PATH = os.path.join(APP_SUPPORT, "config.json")
DB_PATH = os.path.join(APP_SUPPORT, "spambuster.db")
LOG_PATH = os.path.join(LOG_DIR, "spambuster.log")

# Where the running code lives (the repo checkout). Used by the updater.
APP_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WEB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web")


def ensure_dirs():
    for d in (APP_SUPPORT, LOG_DIR, TOKEN_DIR):
        os.makedirs(d, exist_ok=True)
    # Keep tokens private.
    try:
        os.chmod(TOKEN_DIR, 0o700)
    except Exception:
        pass
