# 🛡️ Spam Buster

A self-learning junk-mail cleaner for macOS. It watches your Hotmail/Outlook.com
**Junk** folders, learns which messages you delete unread, and — once you trust
it — auto-deletes high-confidence spam into a **recoverable quarantine**.

- **Works with any client** (Outlook, Apple Mail, web) because it talks to the
  mailbox itself via the Microsoft Graph API, not the app windows.
- **Transparent brain** — every decision is a sum of named signals (sender,
  domain, subject words) you can inspect in the Reports screen.
- **Safe by default** — starts in *observe-only* mode, deletes nothing until you
  flip the switch, and everything is undoable.
- **Menu-bar app** with a polished dashboard, quarantine + undo, reports, and a
  one-click updater.
- **Universal** — install on any Mac (yours, your partner's) with one command.

## Install

```bash
git clone <your-repo-url> "Spam Buster"
cd "Spam Buster"
./install.sh
```

Then open **http://127.0.0.1:7676** (or the 🛡️ menu-bar icon) and:

1. **Settings → Microsoft connection**: paste your Azure *Application (client) ID*
   (see below).
2. **Add your two accounts** and click **Connect** — sign in once per account in
   the browser (device-code, no password stored).
3. Leave it in **Observe** mode for a while, then switch to **Auto-delete** when
   the Reports screen looks right.

## Getting a Microsoft app ID (free, ~2 min)

1. Go to <https://entra.microsoft.com> → **App registrations** → **New registration**.
2. Name: *Spam Buster*. Supported account types: **Personal Microsoft accounts**.
3. After creating it, open **Authentication** → enable **Allow public client flows**.
4. Copy the **Application (client) ID** and paste it into Spam Buster.

Spam Buster requests only the `Mail.ReadWrite` permission (read Junk, move to
Deleted Items, restore).

## How the learning works

- You delete a message **unread** from Junk → confirmed **spam** example.
- You **restore** a quarantined message → confirmed **not-spam** (ham) example.
- Sender, domain and subject-word reputations build up from these signals.
- Auto-delete only fires above your **confidence threshold** *and* after a
  minimum number of confirmations for that sender/domain.

## Updating

Big **Update** button on the Overview screen (and in Settings). It pulls the
latest version from your GitHub repo and restarts. The last-checked time is shown
next to the button.

## Uninstall

```bash
./uninstall.sh            # remove the agent, keep your data
./uninstall.sh --purge    # remove everything
```

Data lives in `~/Library/Application Support/SpamBuster/`.
