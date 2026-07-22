"""Application wiring: start the engine + dashboard server, and (on a Mac GUI
session) a menu-bar item. Falls back to headless if rumps isn't available.
"""

import subprocess
import sys
import threading
import webbrowser

from . import config, database as db, logutil, __version__
from .engine import engine
from . import server as server_mod

log = logutil.get_logger("app")


def _dashboard_url():
    cfg = config.load()
    return f"http://{cfg['server']['host']}:{cfg['server']['port']}"


def start_background():
    """Start engine + Flask server threads. Returns the dashboard URL."""
    engine.start()
    t = threading.Thread(
        target=server_mod.run, kwargs={}, daemon=True, name="flask")
    t.start()
    return _dashboard_url()


def open_dashboard():
    url = _dashboard_url()
    # Prefer a chrome-less native window via pywebview in a helper process.
    try:
        subprocess.Popen([sys.executable, "-m", "spambuster.window", url])
        return
    except Exception as e:  # noqa
        log.info("pywebview window unavailable (%s); opening browser", e)
    webbrowser.open(url)


def run_headless():
    log.info("Spam Buster %s starting (headless)…", __version__)
    start_background()
    try:
        while True:
            threading.Event().wait(3600)
    except KeyboardInterrupt:
        engine.stop()


def run_menubar():
    import rumps

    url = start_background()
    log.info("Spam Buster %s starting (menu bar). Dashboard: %s", __version__, url)

    class SpamBusterApp(rumps.App):
        def __init__(self):
            super().__init__("🛡️", quit_button=None)
            self.menu = [
                rumps.MenuItem("Open Spam Buster", callback=self.on_open),
                None,
                rumps.MenuItem("Scan now", callback=self.on_scan),
                rumps.MenuItem("Pause protection", callback=self.on_pause),
                None,
                rumps.MenuItem("Check for updates", callback=self.on_update),
                rumps.MenuItem("Status: starting…", callback=None),
                None,
                rumps.MenuItem("Quit Spam Buster", callback=self.on_quit),
            ]

        @rumps.timer(15)
        def refresh(self, _):
            st = engine.status
            paused = engine.paused
            self.menu["Pause protection"].title = (
                "Resume protection" if paused else "Pause protection")
            mode = config.load()["detection"]["mode"]
            last = st.get("last_scan")
            when = "never" if not last else _ago(last)
            self.menu["Status: starting…"].title = (
                f"Status: {'paused' if paused else mode} · scanned {when}")
            self.title = "🛡️" if not paused else "🛡️⏸"

        def on_open(self, _):
            open_dashboard()

        def on_scan(self, _):
            engine.wake()
            rumps.notification("Spam Buster", "Scanning", "Checking your Junk folders now.")

        def on_pause(self, _):
            engine.set_paused(not engine.paused)

        def on_update(self, _):
            from . import updater
            res = updater.check_for_updates()
            rumps.notification("Spam Buster", "Update check", res.get("message", ""))

        def on_quit(self, _):
            engine.stop()
            rumps.quit_application()

    SpamBusterApp().run()


def _ago(ts):
    import time
    d = max(0, int(time.time() - ts))
    if d < 60:
        return f"{d}s ago"
    if d < 3600:
        return f"{d // 60}m ago"
    return f"{d // 3600}h ago"


def main():
    if "--headless" in sys.argv:
        return run_headless()
    try:
        return run_menubar()
    except Exception as e:  # noqa
        log.warning("menu bar failed (%s); running headless", e)
        return run_headless()
