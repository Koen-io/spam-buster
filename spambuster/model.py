"""Online logistic-regression spam scorer.

Learns feature weights incrementally from every labelled example (you delete →
spam, you rescue → ham). It sharpens and *calibrates* the confidence, but:

- It only takes over once it has seen enough examples (MIN_EXAMPLES), so a fresh
  install behaves exactly like the transparent reputation scorer — no regression.
- Features are sender / domain / subject-words only. Authentication and phishing
  signals stay as separate, explainable engine overrides (no double-counting).
- Weights live in the DB so the model persists and can be exported.
"""

import math
import threading

from . import database as db, detector

LR = 0.20          # learning rate
L2 = 1e-4          # weight decay
MIN_EXAMPLES = 15  # below this, defer to the reputation scorer

_lock = threading.Lock()
_W = None          # in-memory weight cache


def _load():
    global _W
    if _W is None:
        _W = db.get_all_weights()
    return _W


def _sigmoid(z):
    if z < -35:
        return 0.0
    if z > 35:
        return 1.0
    return 1.0 / (1.0 + math.exp(-z))


def featurize(message):
    """Sparse feature dict for a message."""
    f = detector.features(message)
    feats = {"__bias__": 1.0}
    if f["sender"]:
        feats[f"snd:{f['sender']}"] = 1.0
    if f["domain"]:
        feats[f"dom:{f['domain']}"] = 1.0
    for tok in set(f["tokens"]):
        feats[f"tok:{tok}"] = 1.0
    return feats


def examples():
    return int(db.get_meta("lr_examples", 0) or 0)


def is_ready():
    return examples() >= MIN_EXAMPLES


def predict(message):
    """Calibrated spam probability from the LR model (0..1)."""
    W = _load()
    feats = featurize(message)
    z = sum(W.get(f, 0.0) * v for f, v in feats.items())
    return _sigmoid(z)


def train(message, label):
    """One SGD step. label: 'spam' -> 1, else 0."""
    y = 1.0 if label == "spam" else 0.0
    with _lock:
        W = _load()
        feats = featurize(message)
        z = sum(W.get(f, 0.0) * v for f, v in feats.items())
        p = _sigmoid(z)
        g = p - y
        changed = {}
        for f, v in feats.items():
            neww = W.get(f, 0.0) - LR * (g * v + L2 * W.get(f, 0.0))
            W[f] = neww
            changed[f] = neww
        db.save_weights(changed)
    db.set_meta("lr_examples", examples() + 1)


def backfill():
    """One-time: replay past labelled events so the model reflects existing history."""
    if examples() > 0:
        return 0
    rows = db.events_for_training()
    n = 0
    for r in rows:
        msg = {"sender": r.get("sender"), "sender_domain": r.get("sender_domain"),
               "sender_name": "", "subject": r.get("subject")}
        train(msg, r["label"])
        n += 1
    return n


def top_signals(limit=30):
    """Most influential learned weights, for the Reports screen."""
    W = _load()
    items = [(f, w) for f, w in W.items() if f != "__bias__"]
    items.sort(key=lambda x: abs(x[1]), reverse=True)
    return items[:limit]
