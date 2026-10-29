"""Main window: header bar with view switcher, demo banner, toasts."""

from .api import DEMO_BANNER_TEXT
from .pages.about import AboutPage
from .pages.access import AccessPage
from .pages.apps import AppsPage
from .pages.common import Adw, Gtk
from .pages.devices import DevicesPage
from .pages.help import HelpPage
from .pages.home import HomePage
from .pages.updates import UpdatesPage

PAGE_CLASSES = (HomePage, AppsPage, UpdatesPage, AccessPage, DevicesPage, HelpPage, AboutPage)


class WorkplaceWindow(Adw.ApplicationWindow):
    def __init__(self, app, client, demo_reason=None, start_page=None):
        super().__init__(application=app, title="Workplace", default_width=920, default_height=720,
                         width_request=360, height_request=480)
        self.client = client

        self.stack = Adw.ViewStack()
        self.pages = []
        for cls in PAGE_CLASSES:
            page = cls(self)
            self.pages.append(page)
            self.stack.add_titled_with_icon(page, cls.page_id, cls.title, cls.icon_name)
        if start_page:
            self.stack.set_visible_child_name(start_page)

        header = Adw.HeaderBar()
        header.set_title_widget(Adw.ViewSwitcher(stack=self.stack,
                                                 policy=Adw.ViewSwitcherPolicy.WIDE))
        refresh = Gtk.Button(icon_name="view-refresh-symbolic", tooltip_text="Refresh")
        refresh.connect("clicked", lambda *_: self.refresh_all())
        header.pack_start(refresh)

        self.toasts = Adw.ToastOverlay(child=self.stack)
        view = Adw.ToolbarView(content=self.toasts)
        view.add_top_bar(header)
        if client.is_demo:
            text = DEMO_BANNER_TEXT if not demo_reason else "%s %s" % (DEMO_BANNER_TEXT, demo_reason)
            view.add_top_bar(Adw.Banner(title=text, revealed=True))
        # Narrow windows: switcher moves to the bottom.
        bottom = Adw.ViewSwitcherBar(stack=self.stack)
        view.add_bottom_bar(bottom)
        bp = Adw.Breakpoint.new(Adw.BreakpointCondition.parse("max-width: 600sp"))
        bp.add_setter(bottom, "reveal", True)
        bp.add_setter(header, "show-title", False)
        self.add_breakpoint(bp)
        self.set_content(view)

    def toast(self, text):
        self.toasts.add_toast(Adw.Toast(title=text, timeout=4))

    def refresh_all(self):
        for page in self.pages:
            page.refresh()

    def ask_reason(self, heading, body, on_ok):
        dialog = Adw.MessageDialog(transient_for=self, heading=heading, body=body)
        entry = Gtk.Entry(placeholder_text="Reason")
        dialog.set_extra_child(entry)
        dialog.add_response("cancel", "Cancel")
        dialog.add_response("send", "Send")
        dialog.set_response_appearance("send", Adw.ResponseAppearance.SUGGESTED)

        def on_response(_d, response):
            if response == "send":
                on_ok(entry.get_text())

        dialog.connect("response", on_response)
        dialog.present()

    def explain(self, key, locked, title, reason):
        body = reason if locked else "This setting is not managed. You can change it in Settings."
        dialog = Adw.MessageDialog(transient_for=self, heading=title, body="%s\n\n%s" % (body, key))
        dialog.add_response("ok", "OK")
        dialog.present()
