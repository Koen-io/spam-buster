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

    # wellKnownName is beta-only; detect the Junk folder by name instead.
    junk_names = {"junk", "junk email", "junk e-mail", "ongewenste e-mail",
                  "ongewenste email", "spam", "bulk mail", "bulk email"}

    def wk(name):
        return "junkemail" if (name or "").strip().lower() in junk_names else None

    out = []
    top = _fetch(f"{BASE}/me/mailFolders?$top=100"
                 f"&$select=id,displayName,totalItemCount,childFolderCount")
    for f in top:
        out.append({"id": f["id"], "name": f.get("displayName"),
                    "well_known": wk(f.get("displayName")),
                    "total": f.get("totalItemCount", 0), "depth": 0})
        if f.get("childFolderCount"):
            try:
                kids = _fetch(f"{BASE}/me/mailFolders/{f['id']}/childFolders"
                              f"?$top=100&$select=id,displayName,totalItemCount")
                for k in kids:
                    out.append({"id": k["id"], "name": k.get("displayName"),
                                "well_known": wk(k.get("displayName")),
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
    """Fetch headers + body + reply-to + attachments for deep analysis."""
    url = (f"{BASE}/me/messages/{graph_id}"
           f"?$select=id,internetMessageId,subject,from,replyTo,receivedDateTime,isRead,"
           f"bodyPreview,body,hasAttachments,internetMessageHeaders"
           f"&$expand=attachments($select=name,contentType,size)")
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
    # reply-to domains
    rt = []
    for r0 in (m.get("replyTo") or []):
        addr = ((r0.get("emailAddress") or {}).get("address") or "").lower()
        if "@" in addr:
            rt.append(addr.split("@", 1)[1])
    norm["reply_to_domains"] = rt
    # attachment names/types
    norm["has_attachments"] = bool(m.get("hasAttachments"))
    norm["attachments"] = [
        {"name": a.get("name") or "", "type": a.get("contentType") or ""}
        for a in (m.get("attachments") or [])]
    return norm


# ---- folder resolution + message lookup (for destination-aware learning) ----

def folder_id(token, wellknown):
    """Resolve a well-known folder name (inbox, deleteditems) to its id."""
    r = requests.get(f"{BASE}/me/mailFolders/{wellknown}?$select=id",
                     headers=_headers(token), timeout=TIMEOUT)
    if r.status_code != 200:
        raise GraphError(f"folder_id failed: {r.status_code} {r.text[:150]}")
    return r.json().get("id")


def find_message_folder(token, internet_id):
    """Return the parentFolderId of the message with this internetMessageId, or None."""
    if not internet_id:
        return None
    safe = internet_id.replace("'", "''")
    url = (f"{BASE}/me/messages?$filter=internetMessageId eq '{safe}'"
           f"&$select=id,parentFolderId&$top=1")
    r = requests.get(url, headers=_headers(token), timeout=TIMEOUT)
    if r.status_code != 200:
        return None
    vals = r.json().get("value", [])
    return vals[0].get("parentFolderId") if vals else None


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
