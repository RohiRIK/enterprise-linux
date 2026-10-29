"""Access: request temporary admin / extra roles (just-in-time elevation)."""

from ..api import validate_elevation_request
from .common import Adw, Gtk, Page, button, group, row, when


class AccessPage(Page):
    page_id = "access"
    title = "Access"
    icon_name = "system-users-symbolic"

    def build(self, page):
        r = self.client.list_grants()

        g = group(page, "Your access", r.get("user"))
        g.add(row("Roles", ", ".join(r.get("effective_roles", [])) or "user"))
        for grant in r.get("grants", []):
            gr = row(grant.get("role"), "Ends %s" % when(grant.get("expires_at")),
                     icon_name="changes-allow-symbolic")
            gr.add_suffix(button("End now", lambda role=grant.get("role"): self.run(
                "End access", self.client.revoke_grant, role)))
            g.add(gr)

        if r.get("requests"):
            g = group(page, "Requests")
            for req in r["requests"]:
                g.add(row("%s (%s)" % (req.get("role"), req.get("state")),
                          "%s · %s" % (req.get("id"), req.get("reason"))))

        for role in r.get("requestable_roles", []):
            self._request_group(page, role)

    def _request_group(self, page, role):
        approval = "approved automatically" if role.get("approval") == "auto" else \
            "approved by %s" % role.get("approval", "IT")
        g = group(page, role.get("name", role["id"]),
                  "%s. Up to %d minutes, %s." % (role.get("description", ""),
                                                  role.get("max_minutes", 0), approval))
        reason = Adw.EntryRow(title="Reason")
        g.add(reason)
        minutes = Adw.SpinRow.new_with_range(15, max(15, role.get("max_minutes", 60)), 15)
        minutes.set_title("Minutes")
        minutes.set_value(min(60, role.get("max_minutes", 60)))
        g.add(minutes)
        ticket = Adw.EntryRow(title="Ticket number (optional)")
        g.add(ticket)
        submit = Gtk.Button(label="Send request", halign=Gtk.Align.END, margin_top=12,
                            css_classes=["suggested-action"])

        def on_submit(*_):
            dur = int(minutes.get_value())
            problems = validate_elevation_request(role["id"], reason.get_text(), dur,
                                                  role.get("max_minutes"))
            if problems:
                self.ctx.toast(" ".join(problems))
                return
            self.run("Request", self.client.request_elevation, role["id"], reason.get_text(),
                     dur, ticket.get_text() or None)

        submit.connect("clicked", on_submit)
        g.add(submit)
