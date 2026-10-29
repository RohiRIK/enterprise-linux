"""Devices: USB approval (if policy allows), printers, Bluetooth."""

from .common import Gtk, Page, button, group, row


class DevicesPage(Page):
    page_id = "devices"
    title = "Devices"
    icon_name = "drive-removable-media-symbolic"

    def build(self, page):
        d = self.client.get_peripherals()
        policy = d.get("usb_policy", {})

        g = group(page, "USB devices", policy.get("note"))
        for dev in d.get("usb", []):
            r = row(dev.get("name"), "%s · %s:%s" % (dev.get("class"), dev.get("vendor_id"),
                                                    dev.get("product_id")))
            if dev.get("state") == "blocked" and policy.get("user_approval"):
                r.add_suffix(button("Allow", lambda i=dev["id"]: self.run(
                    "Allow device", self.client.approve_usb_device, i)))
            else:
                r.add_suffix(Gtk.Label(label=dev.get("state", "").capitalize(),
                                       css_classes=["dim-label"]))
            g.add(r)

        g = group(page, "Printers")
        for p in d.get("printers", []):
            sub = p.get("state", "")
            if p.get("default"):
                sub += " · default"
            g.add(row(p.get("name"), sub, icon_name="printer-symbolic"))

        bt = d.get("bluetooth", {})
        g = group(page, "Bluetooth", "On" if bt.get("enabled") else "Off")
        for dev in bt.get("devices", []):
            g.add(row(dev.get("name"), "Connected" if dev.get("connected") else "Paired",
                      icon_name="bluetooth-active-symbolic"))
