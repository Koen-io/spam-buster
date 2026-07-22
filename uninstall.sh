#!/bin/bash
# Remove the Spam Buster background agent. Keeps your data unless you pass --purge.
set -e
LABEL="com.spambuster.agent"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
SUPPORT="$HOME/Library/Application Support/SpamBuster"

echo "→ Stopping agent…"
launchctl unload "$PLIST" 2>/dev/null || true
rm -f "$PLIST"
echo "✅ Agent removed."

if [ "$1" == "--purge" ]; then
  rm -rf "$SUPPORT"
  echo "🗑️  Removed all Spam Buster data, settings and sign-ins."
else
  echo "ℹ️  Your database, settings and sign-ins are kept at:"
  echo "   $SUPPORT"
  echo "   Re-run install.sh to start again, or pass --purge to delete everything."
fi
