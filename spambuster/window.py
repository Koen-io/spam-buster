"""Helper process: show the dashboard in a chrome-less native window.

Run as:  python -m spambuster.window http://127.0.0.1:7676
Kept separate from the menu-bar process so their UI run-loops don't clash.
"""

import sys


def main():
    url = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:7676"
    try:
        import webview
        webview.create_window("Spam Buster", url, width=1120, height=780,
                              min_size=(900, 640))
        webview.start()
    except Exception:
        import webbrowser
        webbrowser.open(url)


if __name__ == "__main__":
    main()
