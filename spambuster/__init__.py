"""Spam Buster — a self-learning junk-mail cleaner for macOS.

Watches your Hotmail/Outlook.com Junk folders via the Microsoft Graph API,
learns which messages you delete unread, and (once you trust it) auto-deletes
high-confidence spam into a recoverable quarantine.
"""

import os

__version__ = "1.0.0"

# Read the packaged VERSION file if present (kept in sync by the updater).
try:
    _vfile = os.path.join(os.path.dirname(os.path.dirname(__file__)), "VERSION")
    with open(_vfile, "r", encoding="utf-8") as _f:
        __version__ = _f.read().strip() or __version__
except Exception:
    pass

APP_NAME = "Spam Buster"
