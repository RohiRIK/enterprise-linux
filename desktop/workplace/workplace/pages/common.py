"""Shared helpers for pages. Requires GTK 4 and libadwaita >= 1.4."""

import datetime as _dt

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gtk  # noqa: E402

from ..api import ControlError  # noqa: E402

STATUS_ICONS = {
    "pass": "emblem-ok-symbolic",
    "warn": "dialog-warning-symbolic",
    "fail": "dialog-error-symbolic",
    "unknown": "dialog-question-symbolic",
}
STATUS_CSS = {"pass": "success", "warn": "warning", "fail": "error", "unknown": "dim-label"}


class Page(Adw.Bin):
    """A tab. Subclasses implement ``build(page)`` filling an Adw.PreferencesPage.

    ``ctx`` is the window; it provides ``client``, ``toast(text)`` and
    ``refresh_all()``. ``refresh()`` rebuilds the page from fresh API data.
    """

    page_id = ""
    title = ""
    icon_name = ""

    def __init__(self, ctx):
        super().__init__()
        self.ctx = ctx
        self.refresh()

    @property
    def client(self):
        return self.ctx.client

    def refresh(self):
        page = Adw.PreferencesPage()
        try:
            self.build(page)
        except ControlError as exc:
            self.set_child(Adw.StatusPage(
                icon_name="network-offline-symbolic",
                title="Could not reach the device management service",
                description=str(exc)))
            return
        self.set_child(page)

    def build(self, page):
        raise NotImplementedError

    def run(self, label, func, *args):
        """Call an API method, show the result as a toast, refresh all pages."""
        try:
            result = func(*args) or {}
        except (ControlError, ValueError) as exc:
            self.ctx.toast("%s failed: %s" % (label, exc))
            return None
        self.ctx.toast(result.get("message") or "%s: done" % label)
        self.ctx.refresh_all()
        return result


def group(page, title, description=None):
    g = Adw.PreferencesGroup(title=title)
    if description:
        g.set_description(description)
    page.add(g)
    return g


def row(title, subtitle=None, icon_name=None):
    r = Adw.ActionRow(title=title)
    if subtitle:
        r.set_subtitle(str(subtitle))
    if icon_name:
        r.add_prefix(Gtk.Image.new_from_icon_name(icon_name))
    return r


def button(label, callback, *, suggested=False, destructive=False):
    b = Gtk.Button(label=label, valign=Gtk.Align.CENTER)
    if suggested:
        b.add_css_class("suggested-action")
    if destructive:
        b.add_css_class("destructive-action")
    b.connect("clicked", lambda *_: callback())
    return b


def status_icon(status):
    img = Gtk.Image.new_from_icon_name(STATUS_ICONS.get(status, STATUS_ICONS["unknown"]))
    img.add_css_class(STATUS_CSS.get(status, "dim-label"))
    return img


def when(iso_text):
    """Short human time for an ISO 8601 timestamp, e.g. '12 minutes ago'."""
    if not iso_text:
        return "never"
    try:
        then = _dt.datetime.fromisoformat(iso_text)
    except ValueError:
        return iso_text
    now = _dt.datetime.now(then.tzinfo)
    secs = int((now - then).total_seconds())
    future = secs < 0
    secs = abs(secs)
    for unit, size in (("day", 86400), ("hour", 3600), ("minute", 60)):
        if secs >= size:
            n = secs // size
            text = "%d %s%s" % (n, unit, "" if n == 1 else "s")
            return ("in " + text) if future else (text + " ago")
    return "just now"
