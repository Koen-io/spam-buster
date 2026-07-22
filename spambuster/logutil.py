"""Rotating file logger shared across modules."""

import logging
import logging.handlers

from . import paths

_configured = False


def _configure():
    global _configured
    if _configured:
        return
    paths.ensure_dirs()
    root = logging.getLogger("spambuster")
    root.setLevel(logging.INFO)
    handler = logging.handlers.RotatingFileHandler(
        paths.LOG_PATH, maxBytes=1_000_000, backupCount=3, encoding="utf-8"
    )
    handler.setFormatter(logging.Formatter(
        "%(asctime)s [%(name)s] %(levelname)s: %(message)s"))
    root.addHandler(handler)
    # Also echo to stderr (visible under launchd logs).
    stream = logging.StreamHandler()
    stream.setFormatter(logging.Formatter("[%(name)s] %(levelname)s: %(message)s"))
    root.addHandler(stream)
    _configured = True


def get_logger(name):
    _configure()
    return logging.getLogger("spambuster." + name)


def tail(lines=200):
    try:
        with open(paths.LOG_PATH, "r", encoding="utf-8") as f:
            return "".join(f.readlines()[-lines:])
    except Exception:
        return ""
