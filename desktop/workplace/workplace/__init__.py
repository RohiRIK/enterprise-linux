"""Workplace: the IT self-service app for enterprise-linux (skeleton).

Status: design-stage skeleton. The control daemon ``eld`` that this app talks
to does not exist yet, so on every real system today the app runs on clearly
labelled demo data.

Only stdlib modules are imported here so that ``workplace.api`` and the tests
can be used on machines without PyGObject.
"""

APP_ID = "org.enterpriselinux.Workplace"
APP_NAME = "Workplace"
__version__ = "0.1.0.dev0"

# Page ids, in display order. They match the tabs in docs/DESKTOP-UX.md section 4.
PAGES = ("home", "apps", "updates", "access", "devices", "help", "about")
