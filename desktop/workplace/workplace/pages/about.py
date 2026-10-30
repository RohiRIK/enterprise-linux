"""About: device identity, who manages it, and what they can and cannot see."""

from .. import APP_NAME, __version__
from .common import Page, group, row, when


class AboutPage(Page):
    page_id = "about"
    title = "About"
    icon_name = "computer-symbolic"

    def build(self, page):
        info = self.client.get_device_info()
        dev, os_ = info.get("device", {}), info.get("os", {})
        enr = dev.get("enrollment", {})

        g = group(page, "This device")
        g.add(row("Name", dev.get("name")))
        g.add(row("Model", dev.get("model")))
        g.add(row("Serial number", dev.get("serial")))
        g.add(row("System", "%s %s" % (os_.get("distro", ""), os_.get("version", ""))))
        g.add(row("Image", "%s (%s)" % (os_.get("image_id"), os_.get("build_hash"))))

        g = group(page, "Management")
        g.add(row("Managed by", enr.get("managed_by")))
        g.add(row("Service", enr.get("service")))
        g.add(row("Enrolled", when(enr.get("enrolled_at"))))

        privacy = dev.get("privacy", {})
        g = group(page, "What your organization can see")
        for item in privacy.get("can_see", []):
            g.add(row(item, icon_name="eye-open-negative-filled-symbolic"))
        g = group(page, "What your organization cannot see")
        for item in privacy.get("cannot_see", []):
            g.add(row(item, icon_name="eye-not-looking-symbolic"))

        g = group(page, APP_NAME)
        g.add(row("Version", __version__))
        g.add(row("Data source", self.client.source_description))
