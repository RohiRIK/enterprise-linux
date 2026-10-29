"""Help: contact IT, open a ticket with diagnostics, remote assist."""

from .common import Adw, Gtk, Page, button, group, row


class HelpPage(Page):
    page_id = "help"
    title = "Help"
    icon_name = "help-browser-symbolic"

    def build(self, page):
        s = self.client.get_support_info()

        g = group(page, s.get("org_name", "IT support"), s.get("hours"))
        g.add(row("Email", s.get("email"), icon_name="mail-unread-symbolic"))
        g.add(row("Phone", s.get("phone"), icon_name="call-start-symbolic"))
        if s.get("portal_url"):
            g.add(row("Help portal", s["portal_url"], icon_name="web-browser-symbolic"))

        g = group(page, "Open a ticket")
        summary = Adw.EntryRow(title="What is the problem?")
        g.add(summary)
        details = Adw.EntryRow(title="Details (optional)")
        g.add(details)
        attach = Adw.SwitchRow(title="Attach diagnostics",
                               subtitle="System logs only. No personal files.", active=True)
        g.add(attach)
        send = Gtk.Button(label="Send ticket", halign=Gtk.Align.END, margin_top=12,
                          css_classes=["suggested-action"])
        send.connect("clicked", lambda *_: self.run(
            "Ticket", self.client.open_ticket, summary.get_text(), details.get_text(),
            attach.get_active()))
        g.add(send)

        g = group(page, "More")
        r = row("Collect diagnostics", "Creates a log bundle IT can ask for.")
        r.add_suffix(button("Collect", lambda: self.run("Diagnostics", self.client.collect_logs)))
        g.add(r)
        if s.get("remote_assist_available"):
            r = row("Remote assist", "IT can see your screen only after you accept.")
            r.add_suffix(button("Start", lambda: self.run("Remote assist",
                                                          self.client.start_remote_assist)))
            g.add(r)
