"""Dashboard window: a chrome-less native macOS window (WKWebView via pywebview).

Launched through the app bundle executable in "window" mode, so macOS shows it
as "Spam Buster" with the real icon. Falls back to the browser if pywebview or
its native deps are unavailable.
"""

import os
import sys


def _become_regular_app():
    """Show a real Dock icon for the window even though the agent is LSUIElement."""
    try:
        from AppKit import (NSApplication, NSApplicationActivationPolicyRegular,
                            NSImage)
        app = NSApplication.sharedApplication()
        app.setActivationPolicy_(NSApplicationActivationPolicyRegular)
        from . import paths
        icon_path = os.path.join(paths.ASSETS_DIR, "AppIcon-512.png")
        if os.path.exists(icon_path):
            img = NSImage.alloc().initWithContentsOfFile_(icon_path)
            if img:
                app.setApplicationIconImage_(img)
        app.activateIgnoringOtherApps_(True)
    except Exception:
        pass


def main(url=None):
    url = url or "http://127.0.0.1:7676"
    try:
        import webview
        _become_regular_app()
        webview.create_window("Spam Buster", url, width=1160, height=820,
                              min_size=(940, 660))
        webview.start()
    except Exception:
        import webbrowser
        webbrowser.open(url)


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else None)
