"""Entry point: ``python3 -m workplace [--demo] [--page ID] [--explain KEY]``."""

import argparse
import sys

from . import APP_ID, PAGES, __version__
from .api import select_client
from .locked import explain, read_lock_files


def parse_args(argv):
    p = argparse.ArgumentParser(prog="workplace", description="IT self-service app (skeleton).")
    p.add_argument("--demo", action="store_true", help="use built-in demo data")
    p.add_argument("--page", choices=PAGES, help="open on this tab")
    p.add_argument("--explain", metavar="KEY",
                   help="explain why a dconf key (e.g. /org/gnome/desktop/session/idle-delay) is managed")
    p.add_argument("--version", action="version", version=__version__)
    return p.parse_args(argv)


def locked_keys(client):
    try:
        keys = client.get_locked_keys()
    except Exception:  # eld down or old API: fall back to the files on disk
        keys = []
    return keys or read_lock_files()


def main(argv=None):
    args = parse_args(sys.argv[1:] if argv is None else argv)
    client, demo_reason = select_client(demo=args.demo)

    # GTK is imported late so --help and --version work without a display.
    from .pages.common import Adw
    from .window import WorkplaceWindow

    app = Adw.Application(application_id=APP_ID)

    def on_activate(app):
        win = app.get_active_window() or WorkplaceWindow(app, client, demo_reason, args.page)
        win.present()
        if args.explain:
            win.explain(args.explain, *explain(args.explain, locked_keys(client)))

    app.connect("activate", on_activate)
    return app.run([sys.argv[0]])


if __name__ == "__main__":
    sys.exit(main())
