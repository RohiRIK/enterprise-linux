"""Updates: pending updates, maintenance window, restart / remind me."""

from .common import Page, button, group, row, when


class UpdatesPage(Page):
    page_id = "updates"
    title = "Updates"
    icon_name = "software-update-available-symbolic"

    def build(self, page):
        u = self.client.get_updates()

        g = group(page, "Schedule", "Your organization installs updates automatically.")
        g.add(row("Maintenance window", u.get("maintenance_window")))
        g.add(row("Next window", when(u.get("next_window"))))
        g.add(row("Last successful update", when(u.get("last_success"))))
        g.add(row("Update ring", u.get("ring")))

        pending = u.get("pending", [])
        g = group(page, "Ready to install" if pending else "Up to date",
                  None if pending else "Nothing is waiting.")
        if pending:
            g.set_header_suffix(button("Install now", lambda: self.run(
                "Install", self.client.install_updates_now), suggested=True))
        for item in pending:
            g.add(row(item.get("name"), "%s → %s · %s" % (item.get("from"), item.get("to"), item.get("kind"))))

        if u.get("reboot_required"):
            left = u.get("deferral_hours_left", 0)
            desc = "A restart finishes installing updates."
            if u.get("deferred_until"):
                desc += " Reminder set for %s." % when(u["deferred_until"])
            g = group(page, "Restart needed", desc)
            r = row("Restart now", "Save your work first.")
            r.add_suffix(button("Restart", lambda: self.run("Restart", self.client.restart_now),
                                destructive=True))
            g.add(r)
            r = row("Remind me in 4 hours", "%d hours of postponing left (set by policy)." % left)
            remind = button("Remind me", lambda: self.run("Remind me", self.client.defer_restart, 4))
            remind.set_sensitive(left >= 4)
            r.add_suffix(remind)
            g.add(r)
