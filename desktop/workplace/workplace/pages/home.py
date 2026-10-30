"""Home / Status: compliance tile with per-check Fix buttons."""

from .common import Gtk, Page, button, group, row, status_icon, when

STATE_TEXT = {
    "green": ("emblem-ok-symbolic", "success", "Your device is in good shape"),
    "amber": ("dialog-warning-symbolic", "warning", "Your device needs attention"),
    "red": ("dialog-error-symbolic", "error", "Your device is not compliant"),
}


class HomePage(Page):
    page_id = "home"
    title = "Status"
    icon_name = "security-high-symbolic"

    def build(self, page):
        c = self.client.get_compliance()
        icon, css, headline = STATE_TEXT.get(
            c.get("state"), ("dialog-question-symbolic", "dim-label", "Status unknown"))

        tile = group(page, "")
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6,
                      margin_top=12, margin_bottom=12)
        img = Gtk.Image.new_from_icon_name(icon)
        img.set_pixel_size(64)
        img.add_css_class(css)
        box.append(img)
        label = Gtk.Label(label=headline)
        label.add_css_class("title-2")
        box.append(label)
        policy = c.get("policy") or {}
        sub = Gtk.Label(label="Policy %s %s · last synced %s" % (
            policy.get("name", "?"), policy.get("version", ""), when(c.get("last_policy_sync"))))
        sub.add_css_class("dim-label")
        box.append(sub)
        tile.add(box)

        checks = group(page, "Checks", "Checked %s" % when(c.get("evaluated_at")))
        checks.set_header_suffix(button("Check again", lambda: self.run(
            "Check", self.client.evaluate_compliance)))
        for check in c.get("checks", []):
            r = row(check.get("title", check.get("id")), check.get("detail"))
            r.add_prefix(status_icon(check.get("status")))
            fix = check.get("fix")
            if fix and check.get("status") in ("warn", "fail"):
                r.add_suffix(button(
                    fix.get("label", "Fix"),
                    lambda f=fix: self.run(f.get("label", "Fix"), self.client.run_action,
                                           f["action"], f.get("params") or {}),
                    suggested=True))
            checks.add(r)
