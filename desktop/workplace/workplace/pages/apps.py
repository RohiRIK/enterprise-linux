"""Apps: curated App Center (bundles, catalog, default apps)."""

from .common import Adw, Gtk, Page, button, group, row

CATEGORIES = [
    ("browser", "Browsers"), ("office", "Office"), ("mail", "Mail and calendar"),
    ("collaboration", "Meetings and chat"), ("development", "Development"),
    ("design", "Design and media"), ("security", "Security tools"),
]
DEFAULT_KINDS = [("browser", "Web browser"), ("office", "Office documents"), ("mail", "Mail")]


class AppsPage(Page):
    page_id = "apps"
    title = "Apps"
    icon_name = "view-app-grid-symbolic"

    def build(self, page):
        catalog = self.client.list_catalog()
        apps = catalog.get("apps", [])
        names = {a["id"]: a["name"] for a in apps}

        self._build_defaults(page, names)

        for cat, title in CATEGORIES:
            items = [a for a in apps if a.get("category") == cat]
            if not items:
                continue
            g = group(page, title)
            for app in items:
                tag = "Open source" if app.get("license_kind") == "open-source" else "Proprietary"
                r = row(app["name"], "%s · %s · %s" % (app.get("summary", ""), tag, app.get("license", "")))
                r.add_suffix(self._action_for(app))
                g.add(r)

        g = group(page, "Bundles", "Groups of apps your organization offers.")
        for b in catalog.get("bundles", []):
            r = row(b["name"], b.get("description"))
            state = "Required" if b.get("required") else ("Installed" if b.get("enabled") else "Available")
            r.add_suffix(Gtk.Label(label=state, css_classes=["dim-label"]))
            g.add(r)

    def _build_defaults(self, page, names):
        defaults = self.client.get_default_apps()
        if not defaults:
            return
        g = group(page, "Default apps", "Which app opens links, documents and mail.")
        for kind, title in DEFAULT_KINDS:
            d = defaults.get(kind)
            if not d:
                continue
            choices = d.get("choices", [])
            combo = Adw.ComboRow(title=title)
            combo.set_model(Gtk.StringList.new([names.get(c, c) for c in choices]))
            if d.get("current") in choices:
                combo.set_selected(choices.index(d["current"]))
            if d.get("locked"):
                combo.set_sensitive(False)
                combo.set_subtitle("Managed by your organization")
            else:
                combo.connect("notify::selected", self._on_default_changed, kind, choices)
            g.add(combo)

    def _on_default_changed(self, combo, _pspec, kind, choices):
        idx = combo.get_selected()
        if 0 <= idx < len(choices):
            self.run("Default app", self.client.set_default_app, kind, choices[idx])

    def _action_for(self, app):
        if app.get("installed"):
            if not app.get("removable", True):
                return Gtk.Label(label="Installed", css_classes=["dim-label"])
            return button("Remove", lambda: self.run("Remove", self.client.remove_app, app["id"]))
        if app.get("request_state") == "pending":
            return Gtk.Label(label="Waiting for approval", css_classes=["dim-label"])
        if app.get("requires_approval"):
            return button("Request", lambda: self.ctx.ask_reason(
                "Request %s" % app["name"], "Why do you need this app?",
                lambda reason: self.run("Request", self.client.request_app, app["id"], reason)))
        return button("Install", lambda: self.run("Install", self.client.install_app, app["id"]),
                      suggested=True)
