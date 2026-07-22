"""SQLite storage for Spam Buster.

Tables
------
seen_messages : the last-known snapshot of each account's Junk folder, so we can
                diff between polls and detect what you deleted unread.
events        : the learning log (deleted-unread => spam, rescued => ham, etc.).
reputation    : aggregated spam/ham counts per sender, domain and word token.
                This is the transparent "brain" the Reports screen reads from.
quarantine    : messages Spam Buster auto-deleted, kept recoverable with undo.
meta          : misc engine state (delta tokens, counters).
"""

import json
import os
import sqlite3
import threading
import time

from . import paths

_lock = threading.RLock()
_conn = None

SCHEMA = """
CREATE TABLE IF NOT EXISTS seen_messages (
    account_id   TEXT NOT NULL,
    graph_id     TEXT NOT NULL,
    internet_id  TEXT,
    sender       TEXT,
    sender_domain TEXT,
    sender_name  TEXT,
    subject      TEXT,
    received     TEXT,
    is_read      INTEGER DEFAULT 0,
    first_seen   REAL,
    last_seen    REAL,
    PRIMARY KEY (account_id, graph_id)
);

CREATE TABLE IF NOT EXISTS events (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ts           REAL,
    account_id   TEXT,
    kind         TEXT,          -- deleted_unread | rescued | marked_not_spam | auto_deleted | marked_spam
    label        TEXT,          -- spam | ham
    source       TEXT,          -- user | engine
    sender       TEXT,
    sender_domain TEXT,
    subject      TEXT,
    confidence   REAL
);

CREATE TABLE IF NOT EXISTS reputation (
    key_type     TEXT NOT NULL,  -- sender | domain | token
    key          TEXT NOT NULL,
    spam_count   REAL DEFAULT 0,
    ham_count    REAL DEFAULT 0,
    updated_at   REAL,
    PRIMARY KEY (key_type, key)
);

CREATE TABLE IF NOT EXISTS quarantine (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id   TEXT,
    graph_id     TEXT,          -- current id (in Deleted Items after move)
    internet_id  TEXT,
    sender       TEXT,
    sender_domain TEXT,
    sender_name  TEXT,
    subject      TEXT,
    received     TEXT,
    deleted_at   REAL,
    confidence   REAL,
    reasons      TEXT,          -- json list of human-readable reasons
    status       TEXT DEFAULT 'quarantined'  -- quarantined | restored | purged
);

CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT
);

CREATE TABLE IF NOT EXISTS weights (
    feature TEXT PRIMARY KEY,
    w REAL
);

CREATE TABLE IF NOT EXISTS analysis (
    account_id    TEXT NOT NULL,
    graph_id      TEXT NOT NULL,
    sender        TEXT,
    sender_domain TEXT,
    subject       TEXT,
    received      TEXT,
    spf           TEXT,
    dkim          TEXT,
    dmarc         TEXT,
    compauth      TEXT,
    authenticated INTEGER,
    spoofing      INTEGER,
    phishing_score INTEGER,
    is_phishing   INTEGER,
    phishing_reasons TEXT,
    trackers      INTEGER,
    tracker_domains  TEXT,
    is_newsletter INTEGER,
    unsub_http    TEXT,
    unsub_oneclick TEXT,
    unsub_mailto  TEXT,
    analyzed_at   REAL,
    PRIMARY KEY (account_id, graph_id)
);

CREATE TABLE IF NOT EXISTS lists (
    kind   TEXT NOT NULL,   -- block_domain | block_sender | allow_sender (friends)
    value  TEXT NOT NULL,
    note   TEXT,
    added  REAL,
    PRIMARY KEY (kind, value)
);
"""


def _connect():
    global _conn
    if _conn is None:
        paths.ensure_dirs()
        _conn = sqlite3.connect(paths.DB_PATH, check_same_thread=False)
        _conn.row_factory = sqlite3.Row
        _conn.executescript(SCHEMA)
        _conn.commit()
    return _conn


def _c():
    return _connect()


# ---------------------------------------------------------------- meta

def get_meta(key, default=None):
    with _lock:
        row = _c().execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        if row is None:
            return default
        try:
            return json.loads(row["value"])
        except Exception:
            return row["value"]


def set_meta(key, value):
    with _lock:
        _c().execute(
            "INSERT INTO meta(key,value) VALUES(?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, json.dumps(value)),
        )
        _c().commit()


# ---------------------------------------------------------------- model weights

def get_all_weights():
    with _lock:
        rows = _c().execute("SELECT feature, w FROM weights").fetchall()
        return {r["feature"]: r["w"] for r in rows}


def save_weights(changed):
    """changed: dict feature -> weight."""
    if not changed:
        return
    with _lock:
        _c().executemany(
            "INSERT INTO weights(feature, w) VALUES(?,?) "
            "ON CONFLICT(feature) DO UPDATE SET w=excluded.w",
            list(changed.items()))
        _c().commit()


# ---------------------------------------------------------------- snapshot

def get_seen_ids(account_id):
    with _lock:
        rows = _c().execute(
            "SELECT graph_id, is_read FROM seen_messages WHERE account_id=?",
            (account_id,),
        ).fetchall()
        return {r["graph_id"]: r["is_read"] for r in rows}


def upsert_seen(account_id, msg):
    now = time.time()
    with _lock:
        _c().execute(
            """INSERT INTO seen_messages
               (account_id, graph_id, internet_id, sender, sender_domain,
                sender_name, subject, received, is_read, first_seen, last_seen)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(account_id, graph_id) DO UPDATE SET
                 is_read=excluded.is_read, last_seen=excluded.last_seen,
                 subject=excluded.subject""",
            (account_id, msg["graph_id"], msg.get("internet_id"), msg.get("sender"),
             msg.get("sender_domain"), msg.get("sender_name"), msg.get("subject"),
             msg.get("received"), 1 if msg.get("is_read") else 0, now, now),
        )
        _c().commit()


def get_seen(account_id, graph_id):
    with _lock:
        row = _c().execute(
            "SELECT * FROM seen_messages WHERE account_id=? AND graph_id=?",
            (account_id, graph_id),
        ).fetchone()
        return dict(row) if row else None


def delete_seen(account_id, graph_id):
    with _lock:
        _c().execute(
            "DELETE FROM seen_messages WHERE account_id=? AND graph_id=?",
            (account_id, graph_id),
        )
        _c().commit()


# ---------------------------------------------------------------- events + learning

def add_event(account_id, kind, label, source, sender=None, sender_domain=None,
              subject=None, confidence=None):
    with _lock:
        _c().execute(
            """INSERT INTO events
               (ts, account_id, kind, label, source, sender, sender_domain, subject, confidence)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (time.time(), account_id, kind, label, source, sender,
             sender_domain, subject, confidence),
        )
        _c().commit()


def bump_reputation(key_type, key, spam=0.0, ham=0.0):
    if not key:
        return
    key = key.lower()
    with _lock:
        _c().execute(
            """INSERT INTO reputation(key_type, key, spam_count, ham_count, updated_at)
               VALUES(?,?,?,?,?)
               ON CONFLICT(key_type, key) DO UPDATE SET
                 spam_count = spam_count + ?,
                 ham_count  = ham_count  + ?,
                 updated_at = ?""",
            (key_type, key, spam, ham, time.time(), spam, ham, time.time()),
        )
        _c().commit()


def get_reputation(key_type, key):
    if not key:
        return None
    with _lock:
        row = _c().execute(
            "SELECT * FROM reputation WHERE key_type=? AND key=?",
            (key_type, key.lower()),
        ).fetchone()
        return dict(row) if row else None


def top_reputation(key_type, limit=50, spammy=True):
    order = "spam_count DESC" if spammy else "ham_count DESC"
    with _lock:
        rows = _c().execute(
            f"SELECT * FROM reputation WHERE key_type=? ORDER BY {order} LIMIT ?",
            (key_type, limit),
        ).fetchall()
        return [dict(r) for r in rows]


# ---------------------------------------------------------------- quarantine

def add_quarantine(item):
    with _lock:
        cur = _c().execute(
            """INSERT INTO quarantine
               (account_id, graph_id, internet_id, sender, sender_domain, sender_name,
                subject, received, deleted_at, confidence, reasons, status)
               VALUES (?,?,?,?,?,?,?,?,?,?,?, 'quarantined')""",
            (item["account_id"], item["graph_id"], item.get("internet_id"),
             item.get("sender"), item.get("sender_domain"), item.get("sender_name"),
             item.get("subject"), item.get("received"), time.time(),
             item.get("confidence"), json.dumps(item.get("reasons", []))),
        )
        _c().commit()
        return cur.lastrowid


def list_quarantine(status="quarantined", limit=500):
    with _lock:
        rows = _c().execute(
            "SELECT * FROM quarantine WHERE status=? ORDER BY deleted_at DESC LIMIT ?",
            (status, limit),
        ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            try:
                d["reasons"] = json.loads(d.get("reasons") or "[]")
            except Exception:
                d["reasons"] = []
            out.append(d)
        return out


def get_quarantine(qid):
    with _lock:
        row = _c().execute("SELECT * FROM quarantine WHERE id=?", (qid,)).fetchone()
        if not row:
            return None
        d = dict(row)
        try:
            d["reasons"] = json.loads(d.get("reasons") or "[]")
        except Exception:
            d["reasons"] = []
        return d


def set_quarantine_status(qid, status, new_graph_id=None):
    with _lock:
        if new_graph_id:
            _c().execute(
                "UPDATE quarantine SET status=?, graph_id=? WHERE id=?",
                (status, new_graph_id, qid),
            )
        else:
            _c().execute("UPDATE quarantine SET status=? WHERE id=?", (status, qid))
        _c().commit()


# ---------------------------------------------------------------- stats

def stats():
    with _lock:
        c = _c()
        def scalar(q, *a):
            r = c.execute(q, a).fetchone()
            return (r[0] if r and r[0] is not None else 0)

        return {
            "spam_examples": scalar("SELECT COUNT(*) FROM events WHERE label='spam'"),
            "ham_examples": scalar("SELECT COUNT(*) FROM events WHERE label='ham'"),
            "auto_deleted": scalar("SELECT COUNT(*) FROM events WHERE kind='auto_deleted'"),
            "auto_deleted_active": scalar(
                "SELECT COUNT(*) FROM quarantine WHERE status='quarantined'"),
            "restored": scalar("SELECT COUNT(*) FROM quarantine WHERE status='restored'"),
            "known_domains": scalar("SELECT COUNT(*) FROM reputation WHERE key_type='domain'"),
            "known_senders": scalar("SELECT COUNT(*) FROM reputation WHERE key_type='sender'"),
            "known_tokens": scalar("SELECT COUNT(*) FROM reputation WHERE key_type='token'"),
        }


# ---------------------------------------------------------------- analysis

def has_analysis(account_id, graph_id):
    with _lock:
        return _c().execute(
            "SELECT 1 FROM analysis WHERE account_id=? AND graph_id=?",
            (account_id, graph_id)).fetchone() is not None


def save_analysis(account_id, msg, a):
    au = a["auth"]; un = a["unsubscribe"]
    with _lock:
        _c().execute(
            """INSERT INTO analysis
               (account_id, graph_id, sender, sender_domain, subject, received,
                spf, dkim, dmarc, compauth, authenticated, spoofing,
                phishing_score, is_phishing, phishing_reasons,
                trackers, tracker_domains, is_newsletter,
                unsub_http, unsub_oneclick, unsub_mailto, analyzed_at)
               VALUES (?,?,?,?,?,?, ?,?,?,?,?,?, ?,?,?, ?,?,?, ?,?,?,?)
               ON CONFLICT(account_id, graph_id) DO UPDATE SET
                 phishing_score=excluded.phishing_score,
                 is_phishing=excluded.is_phishing,
                 analyzed_at=excluded.analyzed_at""",
            (account_id, msg["graph_id"], msg.get("sender"), msg.get("sender_domain"),
             msg.get("subject"), msg.get("received"),
             au["spf"], au["dkim"], au["dmarc"], au["compauth"],
             1 if au["authenticated"] else 0, 1 if au["spoofing"] else 0,
             a["phishing_score"], 1 if a["is_phishing"] else 0,
             json.dumps(a["phishing_reasons"]),
             a["trackers"], json.dumps(a["tracker_domains"]),
             1 if un["is_newsletter"] else 0,
             json.dumps(un["http"]), un["one_click"], un["mailto"],
             time.time()),
        )
        _c().commit()


def get_analysis(account_id, graph_id):
    with _lock:
        row = _c().execute("SELECT * FROM analysis WHERE account_id=? AND graph_id=?",
                           (account_id, graph_id)).fetchone()
        return dict(row) if row else None


def protection_summary():
    with _lock:
        c = _c()
        def sc(q, *a):
            r = c.execute(q, a).fetchone(); return r[0] if r and r[0] is not None else 0
        return {
            "analyzed": sc("SELECT COUNT(*) FROM analysis"),
            "authenticated": sc("SELECT COUNT(*) FROM analysis WHERE authenticated=1"),
            "spoofing": sc("SELECT COUNT(*) FROM analysis WHERE spoofing=1"),
            "phishing": sc("SELECT COUNT(*) FROM analysis WHERE is_phishing=1"),
            "trackers": sc("SELECT COALESCE(SUM(trackers),0) FROM analysis"),
            "newsletters_current": sc(
                "SELECT COUNT(*) FROM analysis a JOIN seen_messages s "
                "ON a.account_id=s.account_id AND a.graph_id=s.graph_id "
                "WHERE a.is_newsletter=1"),
        }


def list_phishing(limit=40):
    with _lock:
        rows = _c().execute(
            "SELECT * FROM analysis WHERE is_phishing=1 ORDER BY analyzed_at DESC LIMIT ?",
            (limit,)).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            try: d["phishing_reasons"] = json.loads(d.get("phishing_reasons") or "[]")
            except Exception: d["phishing_reasons"] = []
            out.append(d)
        return out


def list_newsletters(limit=200):
    """Newsletters currently still in a Junk folder."""
    with _lock:
        rows = _c().execute(
            "SELECT a.* FROM analysis a JOIN seen_messages s "
            "ON a.account_id=s.account_id AND a.graph_id=s.graph_id "
            "WHERE a.is_newsletter=1 ORDER BY a.analyzed_at DESC LIMIT ?",
            (limit,)).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            try: d["unsub_http"] = json.loads(d.get("unsub_http") or "[]")
            except Exception: d["unsub_http"] = []
            out.append(d)
        return out


def recent_spoofing(limit=40):
    with _lock:
        rows = _c().execute(
            "SELECT * FROM analysis WHERE spoofing=1 ORDER BY analyzed_at DESC LIMIT ?",
            (limit,)).fetchall()
        return [dict(r) for r in rows]


# ---------------------------------------------------------------- lists

def list_add(kind, value, note=None):
    value = (value or "").strip().lower()
    if not value:
        return False
    with _lock:
        _c().execute(
            "INSERT INTO lists(kind, value, note, added) VALUES(?,?,?,?) "
            "ON CONFLICT(kind, value) DO UPDATE SET note=excluded.note",
            (kind, value, note, time.time()),
        )
        _c().commit()
    return True


def list_remove(kind, value):
    with _lock:
        _c().execute("DELETE FROM lists WHERE kind=? AND value=?",
                     (kind, (value or "").strip().lower()))
        _c().commit()


def list_all(kind):
    with _lock:
        rows = _c().execute(
            "SELECT * FROM lists WHERE kind=? ORDER BY added DESC", (kind,)
        ).fetchall()
        return [dict(r) for r in rows]


def list_has(kind, value):
    if not value:
        return False
    with _lock:
        row = _c().execute(
            "SELECT 1 FROM lists WHERE kind=? AND value=?",
            (kind, value.strip().lower()),
        ).fetchone()
        return row is not None


def recent_events(limit=100):
    with _lock:
        rows = _c().execute(
            "SELECT * FROM events ORDER BY ts DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]


def events_for_training():
    with _lock:
        rows = _c().execute(
            "SELECT sender, sender_domain, subject, label FROM events "
            "WHERE label IN ('spam','ham') ORDER BY ts").fetchall()
        return [dict(r) for r in rows]


# ---------------------------------------------------------------- trends / digest

def daily_counts(days=14):
    """Spam removed per day for the last N days (auto-deleted + deleted-unread)."""
    with _lock:
        rows = _c().execute(
            """SELECT date(ts,'unixepoch','localtime') AS d, COUNT(*) AS n
               FROM events WHERE label='spam'
                 AND ts >= strftime('%s','now','localtime',? )
               GROUP BY d""",
            (f"-{days} days",)).fetchall()
        by = {r["d"]: r["n"] for r in rows}
    # Build a continuous series (fill gaps with 0) using SQLite date math.
    with _lock:
        days_rows = _c().execute(
            "SELECT date('now','localtime', '-'||v||' days') AS d "
            "FROM (WITH RECURSIVE c(v) AS (SELECT 0 UNION ALL SELECT v+1 FROM c WHERE v < ?) "
            "SELECT v FROM c) ORDER BY d", (days - 1,)).fetchall()
    return [{"date": r["d"], "n": by.get(r["d"], 0)} for r in days_rows]


def today_blocked():
    with _lock:
        r = _c().execute(
            "SELECT COUNT(*) FROM events WHERE kind='auto_deleted' "
            "AND ts >= strftime('%s','now','localtime','start of day')").fetchone()
        return r[0] if r and r[0] else 0


def digest(days=7):
    with _lock:
        c = _c()
        def sc(q):
            r = c.execute(q).fetchone(); return r[0] if r and r[0] is not None else 0
        since = f"AND ts >= strftime('%s','now','localtime','-{days} days')"
        return {
            "days": days,
            "spam_removed": sc(f"SELECT COUNT(*) FROM events WHERE kind='auto_deleted' {since}"),
            "learned": sc(f"SELECT COUNT(*) FROM events WHERE kind='deleted_unread' {since}"),
            "restored": sc(f"SELECT COUNT(*) FROM quarantine WHERE status='restored' "
                           f"AND deleted_at >= strftime('%s','now','localtime','-{days} days')"),
            "phishing": sc(f"SELECT COUNT(*) FROM analysis WHERE is_phishing=1 "
                           f"AND analyzed_at >= strftime('%s','now','localtime','-{days} days')"),
            "spoofing": sc(f"SELECT COUNT(*) FROM analysis WHERE spoofing=1 "
                           f"AND analyzed_at >= strftime('%s','now','localtime','-{days} days')"),
            "trackers": sc(f"SELECT COALESCE(SUM(trackers),0) FROM analysis "
                           f"WHERE analyzed_at >= strftime('%s','now','localtime','-{days} days')"),
        }


# ---------------------------------------------------------------- quarantine mgmt

def purge_quarantine_older(retention_days):
    cutoff = time.time() - retention_days * 86400
    with _lock:
        cur = _c().execute(
            "UPDATE quarantine SET status='purged' "
            "WHERE status='quarantined' AND deleted_at < ?", (cutoff,))
        _c().commit()
        return cur.rowcount


def empty_quarantine():
    with _lock:
        cur = _c().execute(
            "UPDATE quarantine SET status='purged' WHERE status='quarantined'")
        _c().commit()
        return cur.rowcount


# ---------------------------------------------------------------- export / import

def export_data():
    with _lock:
        c = _c()
        rep = [dict(r) for r in c.execute("SELECT * FROM reputation").fetchall()]
        lists = [dict(r) for r in c.execute("SELECT * FROM lists").fetchall()]
    return {"version": 1, "reputation": rep, "lists": lists}


def import_data(payload):
    added = {"reputation": 0, "lists": 0}
    for r in (payload.get("reputation") or []):
        try:
            bump_reputation(r["key_type"], r["key"],
                            spam=float(r.get("spam_count", 0)),
                            ham=float(r.get("ham_count", 0)))
            added["reputation"] += 1
        except Exception:
            pass
    for l in (payload.get("lists") or []):
        try:
            list_add(l["kind"], l["value"], note=l.get("note"))
            added["lists"] += 1
        except Exception:
            pass
    return added
