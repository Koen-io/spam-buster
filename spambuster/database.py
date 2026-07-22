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


def recent_events(limit=100):
    with _lock:
        rows = _c().execute(
            "SELECT * FROM events ORDER BY ts DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]
