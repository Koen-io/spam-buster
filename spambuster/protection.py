"""Mailbox-side threat analysis.

Everything here works on data the Microsoft Graph API actually gives us:
message headers and body. We authenticate senders (SPF/DKIM/DMARC), score
links for phishing, count tracking pixels, and detect one-click unsubscribe.

We do NOT pretend to intercept clicks or strip pixels inside Outlook — that's a
mail-client job. What we do is detect these threats in the Junk folder, feed
them into the spam decision, and report them clearly.
"""

import re
from html import unescape
from urllib.parse import urlparse

# ----------------------------------------------------------------- helpers

def headers_map(headers):
    """internetMessageHeaders (list of {name,value}) -> lowercased dict (last wins)."""
    out = {}
    for h in headers or []:
        n = (h.get("name") or "").lower()
        if n:
            out[n] = h.get("value") or ""
    return out


# ----------------------------------------------------------------- auth (SPF/DKIM/DMARC)

def parse_auth(headers):
    """Parse Authentication-Results into spf/dkim/dmarc/compauth verdicts."""
    hm = headers_map(headers)
    raw = " ".join(v for k, v in hm.items()
                   if k in ("authentication-results",
                            "authentication-results-original",
                            "arc-authentication-results"))
    raw_l = raw.lower()

    def grab(mech):
        m = re.search(rf"\b{mech}\s*=\s*([a-z]+)", raw_l)
        return m.group(1) if m else "none"

    result = {
        "spf": grab("spf"),
        "dkim": grab("dkim"),
        "dmarc": grab("dmarc"),
        "compauth": grab("compauth"),
        "have": bool(raw_l.strip()),
    }
    # Overall verdict
    fails = [m for m in ("spf", "dkim", "dmarc") if result[m] == "fail"]
    result["spoofing"] = (result["dmarc"] == "fail"
                          or result["compauth"] == "fail"
                          or len(fails) >= 2)
    result["authenticated"] = (result["dmarc"] == "pass"
                               or (result["spf"] == "pass" and result["dkim"] == "pass"))
    result["fails"] = fails
    return result


# ----------------------------------------------------------------- links / phishing

_HREF_RE = re.compile(r'<a\b[^>]*?href\s*=\s*["\']([^"\']+)["\'][^>]*>(.*?)</a>',
                      re.I | re.S)
_URL_RE = re.compile(r'https?://[^\s"\'<>)]+', re.I)
_SUSPICIOUS_TLDS = {
    "zip", "mov", "xyz", "top", "click", "link", "gq", "tk", "ml", "cf", "ga",
    "work", "country", "kim", "science", "party", "review", "loan", "date",
    "racing", "stream", "download", "men", "rest", "cam", "quest", "sbs",
}
_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "t.ly",
}
_CRED_PHRASES = [
    "verify your account", "verify your identity", "confirm your account",
    "confirm your password", "update your payment", "unusual sign-in",
    "unusual activity", "suspended", "your account will be", "click here to",
    "validate your", "reactivate", "confirm your identity", "security alert",
    "log in to secure", "account locked", "verify now", "confirm now",
    " verifieer", "uw account", "geblokkeerd", "bevestig uw", "wachtwoord",
    "betaling", "beveiliging",
]
_BRANDS = ["paypal", "microsoft", "apple", "amazon", "netflix", "ing", "rabobank",
           "abn amro", "bunq", "postnl", "dhl", "belastingdienst", "google",
           "facebook", "instagram", "outlook", "office365", "coinbase", "binance"]


def _domain_of(url):
    try:
        host = urlparse(url).hostname or ""
        return host.lower()
    except Exception:
        return ""


def _registrable(host):
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def analyze_links(html, sender_domain):
    """Return (links, phishing_score 0-100, reasons)."""
    reasons = []
    score = 0
    links = []
    text_l = re.sub(r"<[^>]+>", " ", html or "").lower()
    sender_reg = _registrable(sender_domain or "")

    anchors = _HREF_RE.findall(html or "")
    bare = _URL_RE.findall(re.sub(_HREF_RE, " ", html or ""))
    all_urls = [a[0] for a in anchors] + bare
    link_domains = set()

    for href, anchor_html in anchors:
        if not href.lower().startswith("http"):
            continue
        href_dom = _domain_of(href)
        if not href_dom:
            continue
        links.append(href_dom)
        link_domains.add(_registrable(href_dom))
        anchor_text = unescape(re.sub(r"<[^>]+>", "", anchor_html)).strip().lower()
        # anchor text claims one domain but href goes elsewhere
        m = re.search(r"([a-z0-9-]+\.[a-z0-9.-]+)", anchor_text)
        if m:
            claimed = _registrable(m.group(1))
            if claimed and claimed not in href_dom and _registrable(href_dom) not in claimed:
                if "." in claimed:
                    reasons.append(f"Link text says “{claimed}” but really goes to {href_dom}")
                    score += 45

    for url in all_urls:
        dom = _domain_of(url)
        if not dom:
            continue
        reg = _registrable(dom)
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", dom):
            reasons.append(f"Link uses a raw IP address ({dom})"); score += 40
        if "xn--" in dom:
            reasons.append("Link uses a punycode/look-alike domain"); score += 40
        if "@" in url.split("//", 1)[-1].split("/", 1)[0]:
            reasons.append("Link hides its real destination with an “@”"); score += 45
        tld = dom.rsplit(".", 1)[-1]
        if tld in _SUSPICIOUS_TLDS:
            reasons.append(f"Link on a high-abuse domain (.{tld})"); score += 18
        if reg in _SHORTENERS:
            reasons.append(f"Hidden link via URL shortener ({reg})"); score += 15

    # brand impersonation: brand named in text, but no link to that brand's domain
    for brand in _BRANDS:
        if brand in text_l and link_domains:
            if not any(brand.replace(" ", "") in d.replace("-", "") for d in link_domains):
                if sender_reg and brand not in sender_reg:
                    reasons.append(f"Mentions “{brand}” but links/sender don’t match it")
                    score += 25
                    break

    # known-malicious link host (abuse.ch URLhaus / ThreatFox)
    try:
        from . import threatfeeds
        for d in link_domains:
            if threatfeeds.is_malicious(d):
                reasons.append(f"Link to a known-malicious site ({d}, abuse.ch)")
                score += 60
                break
    except Exception:
        pass

    # credential-harvest language + a link present
    if link_domains:
        hits = [p for p in _CRED_PHRASES if p in text_l]
        if hits:
            reasons.append(f"Urgent account/credential language (“{hits[0].strip()}”)")
            score += 22

    # de-dup reasons, cap score
    seen = set(); dedup = []
    for r in reasons:
        if r not in seen:
            seen.add(r); dedup.append(r)
    return sorted(link_domains), min(score, 100), dedup[:5]


# ----------------------------------------------------------------- trackers

_TRACKER_DOMAINS = [
    "mailchimp", "list-manage.com", "sendgrid", "sparkpostmail", "mailgun",
    "sailthru", "mixpanel", "hubspot", "marketo", "mktoresp", "constantcontact",
    "cmail", "createsend", "exct.net", "rs6.net", "klaviyo", "omnisend",
    "braze", "iterable", "mandrillapp", "postmark", "pardot", "doubleclick",
    "google-analytics", "mailtrack", "bananatag", "yesware", "streak",
    "getvero", "customer.io", "convertkit", "email.mg", "e.customeriomail",
]
_PIXEL_RE = re.compile(r'<img\b[^>]*>', re.I)


def detect_trackers(html):
    """Count tracking pixels/beacons. Returns (count, sample_domains)."""
    if not html:
        return 0, []
    count = 0
    domains = set()
    for img in _PIXEL_RE.findall(html):
        il = img.lower()
        src_m = re.search(r'src\s*=\s*["\']([^"\']+)["\']', il)
        src = src_m.group(1) if src_m else ""
        dom = _domain_of(src)
        is_pixel = False
        # 1x1 / hidden dimensions
        if re.search(r'(width\s*=\s*["\']?1\b|height\s*=\s*["\']?1\b|'
                     r'width\s*:\s*1px|height\s*:\s*1px|display\s*:\s*none)', il):
            is_pixel = True
        if any(t in src for t in _TRACKER_DOMAINS):
            is_pixel = True
        if re.search(r'(open|track|pixel|beacon|utm_|/o/|/wf/open|/e/o)', src):
            is_pixel = True
        if is_pixel:
            count += 1
            if dom:
                domains.add(_registrable(dom))
    return count, sorted(domains)[:6]


# ----------------------------------------------------------------- unsubscribe

def detect_unsubscribe(headers):
    """Detect List-Unsubscribe; identify RFC-8058 one-click POST support."""
    hm = headers_map(headers)
    lu = hm.get("list-unsubscribe", "")
    lup = hm.get("list-unsubscribe-post", "")
    https_urls = re.findall(r'<\s*(https?://[^>]+)\s*>', lu)
    mailtos = re.findall(r'<\s*mailto:([^>]+)\s*>', lu)
    one_click = None
    if https_urls and "one-click" in lup.lower():
        one_click = https_urls[0]
    return {
        "is_newsletter": bool(lu),
        "http": https_urls,
        "mailto": mailtos[0] if mailtos else None,
        "one_click": one_click,
    }


# ----------------------------------------------------------------- attachments

_DANGEROUS_EXT = {
    "exe", "scr", "com", "pif", "bat", "cmd", "msi", "vbs", "vbe", "js", "jse",
    "jar", "wsf", "wsh", "hta", "ps1", "reg", "lnk", "iso", "img", "apk",
    "docm", "xlsm", "pptm", "dotm",  # macro-enabled office
}
_ARCHIVE_EXT = {"zip", "rar", "7z", "gz", "cab", "ace"}


def check_attachments(attachments):
    """Return (reasons, score_add) for dangerous attachments."""
    reasons, score = [], 0
    for a in attachments or []:
        name = (a.get("name") or "").lower().strip()
        if not name or "." not in name:
            continue
        exts = name.rsplit(".", 2)[1:]
        last = exts[-1]
        if last in _DANGEROUS_EXT:
            reasons.append(f"Dangerous attachment (.{last}: {name[:40]})")
            score += 55
        elif last in {"html", "htm"}:
            reasons.append(f"HTML attachment — common phishing trick ({name[:40]})")
            score += 35
        elif len(exts) == 2 and exts[0] in ("pdf", "doc", "xls", "jpg", "png", "txt"):
            reasons.append(f"Double-extension attachment ({name[:40]})")
            score += 45
    return reasons, min(score, 80)


# ----------------------------------------------------------------- impersonation

_HOMOGLYPH = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s",
                            "7": "t", "8": "b", "$": "s", "|": "l"})


def _norm(s):
    return (s or "").lower().translate(_HOMOGLYPH).replace("-", "")


def _levenshtein(a, b):
    if a == b:
        return 0
    if abs(len(a) - len(b)) > 2:
        return 3
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def check_impersonation(sender_domain, trusted_domains):
    """Sender domain looks like (but isn't) a trusted/friend domain → impersonation."""
    sd = _registrable(sender_domain)
    if not sd:
        return None
    for td in trusted_domains:
        td = _registrable(td)
        if not td or td == sd:
            continue
        if _norm(sd) == _norm(td) or _levenshtein(sd, td) <= 1:
            return f"Sender “{sd}” looks like your trusted “{td}” — possible impersonation"
    return None


# ----------------------------------------------------------------- top-level

def analyze(full_message):
    """full_message: normalized dict incl. 'headers' (list) and 'html' (str)."""
    headers = full_message.get("headers") or []
    html = full_message.get("html") or full_message.get("preview") or ""
    sender_domain = full_message.get("sender_domain") or ""

    auth = parse_auth(headers)
    link_domains, phish_score, phish_reasons = analyze_links(html, sender_domain)
    trackers, tracker_domains = detect_trackers(html)
    unsub = detect_unsubscribe(headers)

    # spoofing lifts the phishing score
    if auth["spoofing"]:
        phish_score = min(100, phish_score + 30)
        phish_reasons = ["Sender failed authentication (possible spoofing)"] + phish_reasons

    # dangerous attachments
    att_reasons, att_score = check_attachments(full_message.get("attachments"))
    if att_reasons:
        phish_score = min(100, phish_score + att_score)
        phish_reasons = att_reasons + phish_reasons

    # From vs Reply-To domain mismatch
    rt = full_message.get("reply_to_domains") or []
    if rt and sender_domain:
        sd = _registrable(sender_domain)
        if all(_registrable(d) != sd for d in rt):
            phish_score = min(100, phish_score + 22)
            phish_reasons = [f"Replies go to a different domain ({_registrable(rt[0])})"] + phish_reasons

    # Friend-impersonation (look-alike of a trusted domain)
    try:
        from . import database as db
        trusted = db.list_values("allow_sender")
        trusted_domains = [d for d in trusted if "@" not in d]
        imp = check_impersonation(sender_domain, trusted_domains)
        if imp:
            phish_score = min(100, phish_score + 45)
            phish_reasons = [imp] + phish_reasons
    except Exception:
        pass

    return {
        "auth": auth,
        "phishing_score": phish_score,
        "phishing_reasons": phish_reasons[:5],
        "is_phishing": phish_score >= 60,
        "trackers": trackers,
        "tracker_domains": tracker_domains,
        "unsubscribe": unsub,
        "link_domains": link_domains[:10],
    }
