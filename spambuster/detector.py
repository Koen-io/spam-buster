"""Transparent spam detector.

Deliberately NOT a black box. Every score is the sum of a few named signals
(sender reputation, domain reputation, subject words) that you deleted or kept
in the past. The Reports screen reads the same numbers, so what you see is
literally what drives the decision.
"""

import math
import re

from . import database as db

_TOKEN_RE = re.compile(r"[a-zA-Z0-9À-ſ]{2,}")

# Very common words carry no signal — ignore them (English + Dutch).
_STOPWORDS = {
    "the", "and", "for", "you", "your", "with", "from", "this", "that", "are",
    "our", "have", "was", "not", "but", "all", "can", "get", "now", "new",
    "de", "het", "een", "van", "voor", "met", "aan", "uw", "je", "op", "en",
    "is", "te", "om", "dat", "die", "zijn", "naar", "ook", "was", "nog",
}


def tokenize(text):
    if not text:
        return []
    toks = []
    for m in _TOKEN_RE.findall(text.lower()):
        if m in _STOPWORDS or m.isdigit():
            continue
        toks.append(m)
    return toks[:40]


def _smoothed_prob(spam, ham, prior=0.5, strength=2.0):
    """Beta-smoothed spam probability. Low evidence stays near the prior."""
    return (spam + prior * strength) / (spam + ham + strength)


def _logit(p):
    p = min(max(p, 1e-4), 1 - 1e-4)
    return math.log(p / (1 - p))


def _sigmoid(x):
    return 1 / (1 + math.exp(-x))


def features(message):
    """Extract the raw features a message contributes."""
    subject = message.get("subject") or ""
    name = message.get("sender_name") or ""
    return {
        "sender": (message.get("sender") or "").lower(),
        "domain": (message.get("sender_domain") or "").lower(),
        "tokens": tokenize(subject + " " + name),
    }


def score(message):
    """Return (probability 0..1, reasons list, decisive_rule bool).

    decisive_rule is True when a sender/domain has a strong, consistent history
    (used together with min_observations to gate auto-deletion).
    """
    f = features(message)

    # ---- hard overrides: your block / allow lists win over everything ----
    if f["sender"] and db.list_has("allow_sender", f["sender"]):
        return 0.0, [f"{f['sender']} is on your Friends list — always kept"], False
    if f["domain"] and db.list_has("allow_sender", f["domain"]):
        return 0.0, [f"Domain {f['domain']} is on your Friends list — always kept"], False
    if f["sender"] and db.list_has("block_sender", f["sender"]):
        return 1.0, [f"{f['sender']} is on your Blocklist — always deleted"], True
    if f["domain"] and db.list_has("block_domain", f["domain"]):
        return 1.0, [f"Domain {f['domain']} is on your Blocklist — always deleted"], True

    log_odds = 0.0
    reasons = []
    decisive = False
    strongest = []  # (abs_contribution, reason)

    # ---- sender (exact address) ----
    rep = db.get_reputation("sender", f["sender"]) if f["sender"] else None
    if rep and (rep["spam_count"] + rep["ham_count"]) >= 1:
        n = rep["spam_count"] + rep["ham_count"]
        p = _smoothed_prob(rep["spam_count"], rep["ham_count"], strength=1.5)
        contrib = _logit(p) * min(n, 6) / 6.0 * 1.5
        log_odds += contrib
        verdict = "spam" if p >= 0.5 else "not spam"
        strongest.append((abs(contrib),
                          f"Sender {f['sender']} looked like {verdict} "
                          f"{int(rep['spam_count'])}/{int(n)} times"))
        if rep["spam_count"] >= 3 and rep["ham_count"] == 0:
            decisive = True

    # ---- domain ----
    rep = db.get_reputation("domain", f["domain"]) if f["domain"] else None
    if rep and (rep["spam_count"] + rep["ham_count"]) >= 1:
        n = rep["spam_count"] + rep["ham_count"]
        p = _smoothed_prob(rep["spam_count"], rep["ham_count"], strength=2.0)
        contrib = _logit(p) * min(n, 10) / 10.0 * 1.8
        log_odds += contrib
        verdict = "spam" if p >= 0.5 else "wanted"
        strongest.append((abs(contrib),
                          f"Domain {f['domain']} was {verdict} "
                          f"{int(rep['spam_count'])}/{int(n)} times"))
        if rep["spam_count"] >= 3 and rep["ham_count"] == 0:
            decisive = True

    # ---- subject / name words (naive-bayes style, capped) ----
    token_contrib = 0.0
    token_reasons = []
    for tok in set(f["tokens"]):
        rep = db.get_reputation("token", tok)
        if not rep:
            continue
        n = rep["spam_count"] + rep["ham_count"]
        if n < 2:
            continue
        p = _smoothed_prob(rep["spam_count"], rep["ham_count"], strength=1.0)
        c = _logit(p) * 0.35
        token_contrib += c
        if abs(c) > 0.2:
            token_reasons.append((abs(c),
                                  f"Word “{tok}” usually means "
                                  f"{'spam' if p >= 0.5 else 'wanted mail'}"))
    # Cap the combined word signal so a long subject can't dominate.
    token_contrib = max(-3.0, min(3.0, token_contrib))
    log_odds += token_contrib
    strongest.extend(token_reasons)

    # ---- soft signals: disposable sender + your "words to watch" ----
    try:
        from . import threatfeeds
        if f["domain"] and threatfeeds.is_disposable(f["domain"]):
            log_odds += 1.1
            strongest.append((1.1, f"Sender uses a disposable/temp-mail domain ({f['domain']})"))
    except Exception:
        pass
    try:
        watch = db.list_values("watch_word")
        if watch:
            for tok in set(f["tokens"]):
                if tok in watch:
                    log_odds += 0.9
                    strongest.append((0.9, f"Contains a word you flagged: “{tok}”"))
    except Exception:
        pass

    prob = _sigmoid(log_odds)

    # Once the online logistic-regression model has enough training, use its
    # calibrated probability (keeps the reputation-based reasons + decisiveness).
    try:
        from . import model
        if model.is_ready():
            lr_prob = model.predict(message)
            blended = 0.15 * prob + 0.85 * lr_prob   # mostly LR, a touch of reputation
            # Never weaken a decisive, consistent reputation rule.
            prob = max(blended, prob) if decisive else blended
    except Exception:
        pass

    strongest.sort(key=lambda x: x[0], reverse=True)
    reasons = [r for _, r in strongest[:4]]
    if not reasons:
        reasons = ["Not enough history yet to judge this sender."]

    return prob, reasons, decisive


def learn(account_id, message, label, source="user", kind=None):
    """Update the brain with a labeled example.

    label: 'spam' or 'ham'.
    """
    f = features(message)
    is_spam = 1.0 if label == "spam" else 0.0
    is_ham = 1.0 - is_spam

    if f["sender"]:
        db.bump_reputation("sender", f["sender"], spam=is_spam, ham=is_ham)
    if f["domain"]:
        db.bump_reputation("domain", f["domain"], spam=is_spam, ham=is_ham)
    for tok in set(f["tokens"]):
        db.bump_reputation("token", tok, spam=is_spam, ham=is_ham)

    db.add_event(
        account_id,
        kind=kind or ("deleted_unread" if label == "spam" else "rescued"),
        label=label, source=source,
        sender=f["sender"], sender_domain=f["domain"],
        subject=message.get("subject"),
    )

    # Update the online logistic-regression model too.
    try:
        from . import model
        model.train(message, label)
    except Exception:
        pass


def rules_summary(min_observations=3, limit=40):
    """Human-readable rules for the Reports screen."""
    auto_rules = []
    for kind, keyname in (("domain", "Domain"), ("sender", "Sender")):
        for r in db.top_reputation(kind, limit=200, spammy=True):
            n = r["spam_count"] + r["ham_count"]
            if r["spam_count"] >= min_observations and r["ham_count"] == 0 and n >= min_observations:
                auto_rules.append({
                    "type": kind,
                    "key": r["key"],
                    "text": f"Auto-delete mail from {keyname.lower()} “{r['key']}”",
                    "evidence": f"deleted {int(r['spam_count'])}/{int(n)} times",
                    "spam": int(r["spam_count"]),
                    "total": int(n),
                })
    auto_rules.sort(key=lambda x: x["spam"], reverse=True)

    spammy_words = []
    for r in db.top_reputation("token", limit=200, spammy=True):
        n = r["spam_count"] + r["ham_count"]
        if n >= 3 and r["spam_count"] / n >= 0.75:
            spammy_words.append({"word": r["key"],
                                 "ratio": round(r["spam_count"] / n, 2),
                                 "total": int(n)})
    spammy_words.sort(key=lambda x: (x["ratio"], x["total"]), reverse=True)

    safe_senders = []
    for r in db.top_reputation("sender", limit=200, spammy=False):
        n = r["spam_count"] + r["ham_count"]
        if r["ham_count"] >= 2 and r["spam_count"] == 0:
            safe_senders.append({"key": r["key"], "kept": int(r["ham_count"])})

    return {
        "auto_rules": auto_rules[:limit],
        "spammy_words": spammy_words[:limit],
        "safe_senders": safe_senders[:limit],
    }
