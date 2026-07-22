"""Thin Microsoft Graph client — only the calls Spam Buster needs.

We target well-known folders ('junkemail', 'deleteditems', 'inbox') so the
Dutch display name "Ongewenste e-mail" doesn't matter — Graph resolves the
right folder on every account regardless of language.
"""

import requests

BASE = "https://graph.microsoft.com/v1.0"
TIMEOUT = 30

SELECT = "id,internetMessageId,subject,from,receivedDateTime,isRead,bodyPreview"


class GraphError(Exception):
    pass


def _headers(token):
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


def _normalize(m):
    frm = (m.get("from") or {}).get("emailAddress") or {}
    addr = (frm.get("address") or "").lower()
    domain = addr.split("@", 1)[1] if "@" in addr else ""
    return {
        "graph_id": m.get("id"),
        "internet_id": m.get("internetMessageId"),
        "sender": addr,
        "sender_name": frm.get("name") or "",
        "sender_domain": domain,
        "subject": m.get("subject") or "",
        "received": m.get("receivedDateTime"),
        "is_read": bool(m.get("isRead")),
        "preview": m.get("bodyPreview") or "",
    }


def whoami(token):
    r = requests.get(f"{BASE}/me?$select=userPrincipalName,mail,displayName",
                     headers=_headers(token), timeout=TIMEOUT)
    if r.status_code != 200:
        raise GraphError(f"whoami failed: {r.status_code} {r.text[:200]}")
    d = r.json()
    return d.get("mail") or d.get("userPrincipalName"), d.get("displayName")


def list_folder_messages(token, folder="junkemail", top=100):
    """Return a folder's messages, newest first. `folder` is a well-known name
    (e.g. 'junkemail') or a folder id."""
    url = (f"{BASE}/me/mailFolders/{folder}/messages"
           f"?$select={SELECT}&$top={top}&$orderby=receivedDateTime desc")
    out = []
    while url and len(out) < top * 3:
        r = requests.get(url, headers=_headers(token), timeout=TIMEOUT)
        if r.status_code != 200:
            raise GraphError(f"list_folder failed: {r.status_code} {r.text[:200]}")
        data = r.json()
        out.extend(_normalize(m) for m in data.get("value", []))
        url = data.get("@odata.nextLink")
        if len(out) >= top:
            break
    return out


def list_junk(token, top=100):
    return list_folder_messages(token, "junkemail", top)


def list_folders(token):
    """List mail folders (top-level + one level of children) for folder pickers."""
    def _fetch(url):
        acc = []
        while url:
            r = requests.get(url, headers=_headers(token), timeout=TIMEOUT)
            if r.status_code != 200:
                raise GraphError(f"list_folders failed: {r.status_code} {r.text[:200]}")
            d = r.json()
            acc.extend(d.get("value", []))
            url = d.get("@odata.nextLink")
        return acc

    out = []
    top = _fetch(f"{BASE}/me/mailFolders?$top=100"
                 f"&$select=id,displayName,wellKnownName,totalItemCount,childFolderCount")
    for f in top:
        out.append({"id": f["id"], "name": f.get("displayName"),
                    "well_known": f.get("wellKnownName"),
                    "total": f.get("totalItemCount", 0), "depth": 0})
        if f.get("childFolderCount"):
            try:
                kids = _fetch(f"{BASE}/me/mailFolders/{f['id']}/childFolders"
                              f"?$top=100&$select=id,displayName,wellKnownName,totalItemCount")
                for k in kids:
                    out.append({"id": k["id"], "name": k.get("displayName"),
                                "well_known": k.get("wellKnownName"),
                                "total": k.get("totalItemCount", 0), "depth": 1})
            except Exception:
                pass
    return out


def get_message(token, graph_id):
    r = requests.get(f"{BASE}/me/messages/{graph_id}?$select={SELECT}",
                     headers=_headers(token), timeout=TIMEOUT)
    if r.status_code == 404:
        return None
    if r.status_code != 200:
        raise GraphError(f"get_message failed: {r.status_code} {r.text[:200]}")
    return _normalize(r.json())


def get_message_full(token, graph_id):
    """Fetch headers + HTML body for deep analysis (auth, phishing, trackers)."""
    url = (f"{BASE}/me/messages/{graph_id}"
           f"?$select=id,internetMessageId,subject,from,receivedDateTime,isRead,"
           f"bodyPreview,body,internetMessageHeaders")
    r = requests.get(url, headers=_headers(token), timeout=TIMEOUT)
    if r.status_code == 404:
        return None
    if r.status_code != 200:
        raise GraphError(f"get_message_full failed: {r.status_code} {r.text[:200]}")
    m = r.json()
    norm = _normalize(m)
    body = m.get("body") or {}
    norm["html"] = body.get("content") or ""
    norm["headers"] = m.get("internetMessageHeaders") or []
    return norm


def move_message(token, graph_id, destination):
    """Move a message to a well-known folder. Returns the NEW message id."""
    r = requests.post(f"{BASE}/me/messages/{graph_id}/move",
                      headers=_headers(token),
                      json={"destinationId": destination}, timeout=TIMEOUT)
    if r.status_code not in (200, 201):
        raise GraphError(f"move failed: {r.status_code} {r.text[:200]}")
    return r.json().get("id")


def soft_delete(token, graph_id):
    """Recoverable delete: move to Deleted Items. Returns new id there."""
    return move_message(token, graph_id, "deleteditems")


def restore_to_inbox(token, graph_id):
    """Undo: move a message (e.g. from Deleted Items) back to the Inbox."""
    return move_message(token, graph_id, "inbox")
