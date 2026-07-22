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


def list_junk(token, top=100):
    """Return the current Junk-folder messages, newest first."""
    url = (f"{BASE}/me/mailFolders/junkemail/messages"
           f"?$select={SELECT}&$top={top}&$orderby=receivedDateTime desc")
    out = []
    while url and len(out) < top * 3:
        r = requests.get(url, headers=_headers(token), timeout=TIMEOUT)
        if r.status_code != 200:
            raise GraphError(f"list_junk failed: {r.status_code} {r.text[:200]}")
        data = r.json()
        out.extend(_normalize(m) for m in data.get("value", []))
        url = data.get("@odata.nextLink")
        if len(out) >= top:
            break
    return out


def get_message(token, graph_id):
    r = requests.get(f"{BASE}/me/messages/{graph_id}?$select={SELECT}",
                     headers=_headers(token), timeout=TIMEOUT)
    if r.status_code == 404:
        return None
    if r.status_code != 200:
        raise GraphError(f"get_message failed: {r.status_code} {r.text[:200]}")
    return _normalize(r.json())


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
