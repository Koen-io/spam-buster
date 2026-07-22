"""Dashboard window.

Shows a frameless splash (no title bar / traffic lights) first, then reveals
the real dashboard window with the normal macOS chrome. The window opens at the
full usable height of the screen. Falls back to the browser if pywebview is
unavailable.
"""

import os
import sys
import threading
import time

APP_NAME = "Spam Buster"
WIDTH = 1180


def _set_process_name():
    """Make the macOS menu-bar app name read 'Spam Buster', not 'Python'.

    The bold application menu is drawn from the running bundle's CFBundleName.
    Framework Python reports 'Python', so we overwrite that key in the in-memory
    bundle info dictionaries BEFORE AppKit builds the menu.
    """
    try:
        from Foundation import NSProcessInfo
        NSProcessInfo.processInfo().setProcessName_(APP_NAME)
    except Exception:
        pass
    try:
        from Foundation import NSBundle
        bundle = NSBundle.mainBundle()
        for getter in ("localizedInfoDictionary", "infoDictionary"):
            info = getattr(bundle, getter)()
            if info is not None:
                info["CFBundleName"] = APP_NAME
                info["CFBundleDisplayName"] = APP_NAME
    except Exception:
        pass


def _screen_size():
    try:
        from AppKit import NSScreen
        vf = NSScreen.mainScreen().visibleFrame()
        return int(vf.size.width), int(vf.size.height)
    except Exception:
        return 1440, 860


def _promote_and_name():
    """Regular Dock app + real icon + correct name (runs after GUI init)."""
    _set_process_name()
    try:
        from AppKit import (NSApplication, NSApplicationActivationPolicyRegular, NSImage)
        app = NSApplication.sharedApplication()
        app.setActivationPolicy_(NSApplicationActivationPolicyRegular)
        from . import paths
        icon = os.path.join(paths.ASSETS_DIR, "AppIcon-512.png")
        if os.path.exists(icon):
            img = NSImage.alloc().initWithContentsOfFile_(icon)
            if img:
                app.setApplicationIconImage_(img)
        app.activateIgnoringOtherApps_(True)
    except Exception:
        pass


def main(url=None):
    url = url or "http://127.0.0.1:7676"
    _set_process_name()
    try:
        import webview
    except Exception:
        import webbrowser
        webbrowser.open(url)
        return

    sw, sh = _screen_size()
    x = max(0, (sw - WIDTH) // 2)

    splash = webview.create_window(
        APP_NAME, url + "/splash", frameless=True, on_top=True,
        width=760, height=500, x=max(0, (sw - 760) // 2), y=max(0, (sh - 500) // 2),
        background_color="#F4F7FB")
    main_win = webview.create_window(
        APP_NAME, url, width=WIDTH, height=sh, x=x, y=0,
        min_size=(960, 640), hidden=True, background_color="#EEF1F6")

    def _sequence():
        _promote_and_name()
        time.sleep(2.5)
        try:
            main_win.show()
        except Exception:
            pass
        time.sleep(0.15)
        try:
            splash.destroy()
        except Exception:
            pass

    webview.start(_sequence)


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else None)
