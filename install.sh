#!/bin/bash
# Spam Buster installer — universal, run on any Mac.
#   ./install.sh
# Sets up the Python environment, builds a native "Spam Buster.app" bundle
# (real icon + name, no "Python" in the dock), and registers a LaunchAgent so
# it runs in the background and starts at login.
set -e

APPDIR="$(cd "$(dirname "$0")" && pwd)"
HOME_DIR="$HOME"
LABEL="com.spambuster.agent"
PLIST="$HOME_DIR/Library/LaunchAgents/$LABEL.plist"
SUPPORT="$HOME_DIR/Library/Application Support/SpamBuster"
ASSETS="$APPDIR/spambuster/assets"
APP_BUNDLE="$HOME_DIR/Applications/Spam Buster.app"
VERSION="$(cat "$APPDIR/VERSION" 2>/dev/null || echo 1.0.0)"

echo "🛡️  Installing Spam Buster $VERSION from: $APPDIR"

# 1. Python + venv
PYBIN="$(command -v python3 || true)"
if [ -z "$PYBIN" ]; then echo "❌ python3 not found. Install it and re-run."; exit 1; fi
if [ ! -d "$APPDIR/.venv" ]; then
  echo "→ Creating virtual environment…"; "$PYBIN" -m venv "$APPDIR/.venv"
fi
VENV_PY="$APPDIR/.venv/bin/python"
echo "→ Installing dependencies…"
"$VENV_PY" -m pip install --upgrade pip >/dev/null
"$VENV_PY" -m pip install -r "$APPDIR/requirements.txt"

# 2. Support dirs
mkdir -p "$SUPPORT/logs" "$SUPPORT/tokens"; chmod 700 "$SUPPORT/tokens"

# 3. Build the .app bundle
echo "→ Building Spam Buster.app…"
rm -rf "$APP_BUNDLE"
mkdir -p "$APP_BUNDLE/Contents/MacOS" "$APP_BUNDLE/Contents/Resources"

# 3a. Icon (.icns) from the PNG set
if command -v iconutil >/dev/null 2>&1; then
  ICONSET="$(mktemp -d)/SpamBuster.iconset"; mkdir -p "$ICONSET"
  cp "$ASSETS/AppIcon-16.png"   "$ICONSET/icon_16x16.png"       2>/dev/null || true
  cp "$ASSETS/AppIcon-32.png"   "$ICONSET/icon_16x16@2x.png"    2>/dev/null || true
  cp "$ASSETS/AppIcon-32.png"   "$ICONSET/icon_32x32.png"       2>/dev/null || true
  cp "$ASSETS/AppIcon-64.png"   "$ICONSET/icon_32x32@2x.png"    2>/dev/null || true
  cp "$ASSETS/AppIcon-128.png"  "$ICONSET/icon_128x128.png"     2>/dev/null || true
  cp "$ASSETS/AppIcon-256.png"  "$ICONSET/icon_128x128@2x.png"  2>/dev/null || true
  cp "$ASSETS/AppIcon-256.png"  "$ICONSET/icon_256x256.png"     2>/dev/null || true
  cp "$ASSETS/AppIcon-512.png"  "$ICONSET/icon_256x256@2x.png"  2>/dev/null || true
  cp "$ASSETS/AppIcon-512.png"  "$ICONSET/icon_512x512.png"     2>/dev/null || true
  cp "$ASSETS/AppIcon-1024.png" "$ICONSET/icon_512x512@2x.png"  2>/dev/null || true
  iconutil -c icns "$ICONSET" -o "$APP_BUNDLE/Contents/Resources/AppIcon.icns" || true
fi

# 3b. Launcher executable (sets SB_APP_EXEC so windows re-enter the bundle)
cat > "$APP_BUNDLE/Contents/MacOS/spambuster" <<LAUNCH
#!/bin/bash
export SB_APP_EXEC="\$0"
DIR="$APPDIR"
exec "$VENV_PY" "\$DIR/run.py" "\$@"
LAUNCH
chmod +x "$APP_BUNDLE/Contents/MacOS/spambuster"

# 3c. Info.plist  (LSUIElement = menu-bar utility, no dock icon for the agent;
#     the dashboard window promotes itself to a normal app at runtime)
cat > "$APP_BUNDLE/Contents/Info.plist" <<PLISTEOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleName</key><string>Spam Buster</string>
  <key>CFBundleDisplayName</key><string>Spam Buster</string>
  <key>CFBundleIdentifier</key><string>com.spambuster.app</string>
  <key>CFBundleExecutable</key><string>spambuster</string>
  <key>CFBundleIconFile</key><string>AppIcon</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>$VERSION</string>
  <key>CFBundleVersion</key><string>$VERSION</string>
  <key>LSUIElement</key><true/>
  <key>LSMinimumSystemVersion</key><string>12.0</string>
  <key>NSHighResolutionCapable</key><true/>
</dict></plist>
PLISTEOF

# refresh icon cache for this bundle
touch "$APP_BUNDLE"

# 4. LaunchAgent -> run the bundle executable (so it's attributed to the app)
echo "→ Registering background agent…"
mkdir -p "$HOME_DIR/Library/LaunchAgents"
cat > "$PLIST" <<AGENT
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>$LABEL</string>
  <key>ProgramArguments</key>
  <array><string>$APP_BUNDLE/Contents/MacOS/spambuster</string></array>
  <key>WorkingDirectory</key><string>$APPDIR</string>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ProcessType</key><string>Interactive</string>
  <key>StandardOutPath</key><string>$SUPPORT/logs/agent.out.log</string>
  <key>StandardErrorPath</key><string>$SUPPORT/logs/agent.err.log</string>
</dict></plist>
AGENT

launchctl unload "$PLIST" 2>/dev/null || true
launchctl load "$PLIST"

echo ""
echo "✅ Spam Buster $VERSION is installed and running."
echo "   • Menu-bar icon (🛡️) is active — click it for Settings & controls."
echo "   • App: $APP_BUNDLE"
echo "   • Dashboard: http://127.0.0.1:7676"
