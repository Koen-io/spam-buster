#!/bin/bash
# Spam Buster installer — universal, run on any Mac.
#   ./install.sh
# Sets up a Python virtual-env, installs dependencies, and registers a
# LaunchAgent so Spam Buster runs in the background and starts at login.
set -e

APPDIR="$(cd "$(dirname "$0")" && pwd)"
HOME_DIR="$HOME"
LABEL="com.spambuster.agent"
PLIST="$HOME_DIR/Library/LaunchAgents/$LABEL.plist"
SUPPORT="$HOME_DIR/Library/Application Support/SpamBuster"

echo "🛡️  Installing Spam Buster from: $APPDIR"

# 1. Python
PYBIN="$(command -v python3 || true)"
if [ -z "$PYBIN" ]; then
  echo "❌ python3 not found. Install it (e.g. 'brew install python') and re-run."
  exit 1
fi

# 2. Virtual environment
if [ ! -d "$APPDIR/.venv" ]; then
  echo "→ Creating virtual environment…"
  "$PYBIN" -m venv "$APPDIR/.venv"
fi
VENV_PY="$APPDIR/.venv/bin/python"
echo "→ Installing dependencies…"
"$VENV_PY" -m pip install --upgrade pip >/dev/null
"$VENV_PY" -m pip install -r "$APPDIR/requirements.txt"

# 3. Support dirs
mkdir -p "$SUPPORT/logs" "$SUPPORT/tokens"
chmod 700 "$SUPPORT/tokens"

# 4. LaunchAgent
echo "→ Registering background agent…"
mkdir -p "$HOME_DIR/Library/LaunchAgents"
sed -e "s#__PYTHON__#$VENV_PY#g" \
    -e "s#__APPDIR__#$APPDIR#g" \
    -e "s#__HOME__#$HOME_DIR#g" \
    "$APPDIR/com.spambuster.agent.plist.template" > "$PLIST"

launchctl unload "$PLIST" 2>/dev/null || true
launchctl load "$PLIST"

echo ""
echo "✅ Spam Buster is installed and running."
echo "   Look for the 🛡️ icon in your menu bar, or open the dashboard:"
echo "   http://127.0.0.1:7676"
echo ""
echo "   Next: open the dashboard → Settings → paste your Microsoft app ID → connect your accounts."
