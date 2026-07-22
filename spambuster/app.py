"""Application wiring: engine + dashboard server + native macOS menu-bar item.

The menu-bar process and the dashboard window are both launched through the
same .app bundle executable (see the launcher in the bundle), so macOS shows
them as "Spam Buster" with the real icon — never as "Python".
"""

import os
import subprocess
import sys
import threading
import time
import webbrowser

from . import config, logutil, paths, __version__
from .engine import engine
from . import server as server_mod

log = logutil.get_logger("app")

MENU_ICON = os.path.join(paths.ASSETS_DIR, "MenuBarIcon.png")


def _dashboard_url(anchor=""):
    cfg = config.load()
    return f"http://{cfg['server']['host']}:{cfg['server']['port']}{anchor}"


def start_background():
    engine.start()
    threading.Thread(target=server_mod.run, daemon=True, name="flask").start()
    return _dashboard_url()


def open_dashboard(anchor=""):
    """Open the dashboard in a native window, attributed to the app bundle."""
    url = _dashboard_url(anchor)
    app_exec = os.environ.get("SB_APP_EXEC")
    try:
        if app_exec and os.path.exists(app_exec):
            # Re-enter the bundle executable in window mode -> shows as "Spam Buster".
            subprocess.Popen([app_exec, "window", url])
            return
        subprocess.Popen([sys.executable, "-m", "spambuster.window", url])
        return
    except Exception as e:  # noqa
        log.info("native window unavailable (%s); opening browser", e)
    webbrowser.open(url)


def run_headless():
    log.info("Spam Buster %s starting (headless)…", __version__)
    start_background()
    try:
        while True:
            threading.Event().wait(3600)
    except KeyboardInterrupt:
        engine.stop()


def _hide_dock_icon():
    """Run the agent as a menu-bar accessory — no Dock icon at all."""
    try:
        from AppKit import NSApplication
        # 1 = NSApplicationActivationPolicyAccessory
        NSApplication.sharedApplication().setActivationPolicy_(1)
    except Exception:
        pass
    try:
        from Foundation import NSProcessInfo
        NSProcessInfo.processInfo().setProcessName_("Spam Buster")
    except Exception:
        pass


def _startup_update_check():
    """On launch: check for updates silently. If one exists, open the dashboard
    so the animated 'What's new' popup shows. If up to date, do nothing."""
    try:
        time.sleep(6)  # let the server come up
        from . import updater
        res = updater.check_for_updates()
        if res.get("available"):
            open_dashboard("#update")
    except Exception as e:  # noqa
        log.debug("startup update check skipped: %s", e)


def run_menubar():
    import rumps

    url = start_background()
    log.info("Spam Buster %s starting (menu bar). Dashboard: %s", __version__, url)
    threading.Thread(target=_startup_update_check, daemon=True).start()

    def _notify(title, message):
        try:
            rumps.notification("Spam Buster", title, message)
        except Exception:
            pass
    engine.ALERT_CALLBACK = _notify

    class SpamBusterApp(rumps.App):
        def __init__(self):
            icon = MENU_ICON if os.path.exists(MENU_ICON) else None
            super().__init__("", icon=icon, template=True, quit_button=None)
            self.menu = [
                rumps.MenuItem("Open Spam Buster", callback=self.on_open),
                rumps.MenuItem("Settings…", callback=self.on_settings),
                None,
                rumps.MenuItem("This week: …", callback=self.on_open),
                rumps.MenuItem("Status: starting…", callback=None),
                None,
                rumps.MenuItem("Scan now", callback=self.on_scan),
                rumps.MenuItem("Pause protection", callback=self.on_pause),
                rumps.MenuItem("Check for updates…", callback=self.on_update),
                None,
                rumps.MenuItem("Quit Spam Buster", callback=self.on_quit),
            ]

        @rumps.timer(1)
        def _accessory(self, _):
            _hide_dock_icon()  # idempotent; ensures no Dock icon for the agent

        @rumps.timer(15)
        def refresh(self, _):
            from . import database as db
            paused = engine.paused
            self.menu["Pause protection"].title = "Resume protection" if paused else "Pause protection"
            mode = config.load()["detection"]["mode"]
            last = engine.status.get("last_scan")
            when = "never" if not last else _ago(last)
            self.menu["Status: starting…"].title = f"Status: {'paused' if paused else mode} · scanned {when}"
            try:
                today = db.today_blocked()
                dg = db.digest(7)
                self.menu["This week: …"].title = (
                    f"This week: {dg['spam_removed']} removed · {dg['phishing']} phishing")
                self.title = f" {today}" if today else ""
            except Exception:
                pass

        def on_open(self, _): open_dashboard()
        def on_settings(self, _): open_dashboard("#settings")
        def on_scan(self, _):
            engine.wake(); rumps.notification("Spam Buster", "Scanning", "Checking your Junk folders now.")
        def on_pause(self, _): engine.set_paused(not engine.paused)
        def on_update(self, _):
            from . import updater
            res = updater.check_for_updates()
            rumps.notification("Spam Buster", "Update check", res.get("message", ""))
            open_dashboard()  # open dashboard so the animated popup is visible
        def on_quit(self, _): engine.stop(); rumps.quit_application()

    SpamBusterApp().run()


def _ago(ts):
    import time
    d = max(0, int(time.time() - ts))
    if d < 60: return f"{d}s ago"
    if d < 3600: return f"{d//60}m ago"
    return f"{d//3600}h ago"


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "window":
        from .window import main as window_main
        return window_main(sys.argv[2] if len(sys.argv) > 2 else None)
    if "--headless" in sys.argv:
        return run_headless()
    try:
        return run_menubar()
    except Exception as e:  # noqa
        log.warning("menu bar failed (%s); running headless", e)
        return run_headless()
