"""Open-source threat intelligence feeds.

Sources (all free / open):
  • abuse.ch URLhaus  — known malware/phishing URLs (needs a free Auth-Key)
  • abuse.ch ThreatFox — domain indicators of compromise (needs Auth-Key)
  • disposable-email-domains — community list of throwaway/temp-mail domains (no key)

Feeds are cached in the local DB so lookups are instant and work offline. We
store *registrable* domains (example.com) and match link hosts / sender domains
against them.
"""

import csv
import datetime
import io
import re
import threading
from urllib.parse import urlparse

import requests

from . import config, database as db, logutil

log = logutil.get_logger("threatfeeds")

DISPOSABLE_URL = ("https://raw.githubusercontent.com/disposable-email-domains/"
                  "disposable-email-domains/master/disposable_email_blocklist.conf")
URLHAUS_CSV = "https://urlhaus.abuse.ch/downloads/csv_recent/"
THREATFOX_CSV = "https://threatfox.abuse.ch/export/csv/domains/recent/"

TIMEOUT = 60
_lock = threading.Lock()
_updating = False


def _registrable(host):
    host = (host or "").strip().lower().rstrip(".")
    if not host or re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
        return host
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


# ---------------------------------------------------------------- lookups

def is_malicious(domain):
    """Is this domain on a malicious-URL / IOC feed?"""
    return db.is_threat(_registrable(domain), ("urlhaus", "threatfox")) is not None


def is_disposable(domain):
    return db.is_threat(_registrable(domain), ("disposable",)) is not None


def counts():
    return db.threat_counts()


# ---------------------------------------------------------------- fetchers

def _fetch(url, key=None):
    headers = {"User-Agent": "SpamBuster/1.0"}
    if key:
        headers["Auth-Key"] = key
    r = requests.get(url, headers=headers, timeout=TIMEOUT)
    r.raise_for_status()
    return r.text


def update_disposable():
    text = _fetch(DISPOSABLE_URL)
    doms = [ln.strip().lower() for ln in text.splitlines()
            if ln.strip() and not ln.startswith("#")]
    return db.replace_threat("disposable", doms)


def update_urlhaus(key):
    text = _fetch(URLHAUS_CSV, key)
    hosts = set()
    for row in csv.reader(io.StringIO(text)):
        if not row or row[0].startswith("#") or len(row) < 3:
            continue
        try:
            host = urlparse(row[2].strip().strip('"')).hostname
        except Exception:
            host = None
        if host:
            hosts.add(_registrable(host))
    return db.replace_threat("urlhaus", hosts)


def update_threatfox(key):
    text = _fetch(THREATFOX_CSV, key)
    doms = set()
    for row in csv.reader(io.StringIO(text)):
        if not row or row[0].startswith("#"):
            continue
        for cell in row:
            c = cell.strip().strip('"').lower()
            if "." in c and " " not in c and "/" not in c and "@" not in c:
                doms.add(_registrable(c))
                break
    return db.replace_threat("threatfox", doms)


def update_all():
    """Refresh all configured feeds. Safe to call in a background thread."""
    global _updating
    with _lock:
        if _updating:
            return {"status": "already_running"}
        _updating = True
    result = {}
    try:
        cfg = config.load()
        key = (cfg.get("threat") or {}).get("abuse_ch_key", "").strip()
        try:
            result["disposable"] = update_disposable()
        except Exception as e:  # noqa
            result["disposable_error"] = str(e)
            log.warning("disposable feed failed: %s", e)
        if key:
            for name, fn in (("urlhaus", update_urlhaus), ("threatfox", update_threatfox)):
                try:
                    result[name] = fn(key)
                except Exception as e:  # noqa
                    result[name + "_error"] = str(e)
                    log.warning("%s feed failed: %s", name, e)
        else:
            result["note"] = "Add a free abuse.ch Auth-Key to enable URLhaus/ThreatFox."
        summary = ", ".join(f"{k}: {v}" for k, v in result.items() if isinstance(v, int))
        config.update({"threat": {
            "last_update": datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
            "last_result": summary or "no feeds updated"}})
        log.info("threat feeds updated: %s", result)
    finally:
        with _lock:
            _updating = False
    return result


def update_async():
    threading.Thread(target=update_all, daemon=True).start()


def maybe_update():
    """Refresh if enabled and older than a day (called from the engine)."""
    cfg = config.load()
    th = cfg.get("threat") or {}
    if not th.get("enabled", True) or not th.get("auto_update", True):
        return
    last = th.get("last_update")
    stale = True
    if last:
        try:
            dt = datetime.datetime.fromisoformat(last)
            stale = (datetime.datetime.now(dt.tzinfo) - dt).total_seconds() > 86400
        except Exception:
            stale = True
    if stale:
        update_async()
