"""Thin client for the enterprise-linux Control API (stdlib only, no gi).

The Control API is specified in docs/CONTROL-API.md. It is served by the
control daemon ``eld``, which has NOT been built yet. This module therefore
ships two implementations of one interface:

* :class:`RestClient` speaks REST/JSON over the local Unix socket
  ``/run/eld/api.sock`` (``GET /v1/facts/<provider>``,
  ``POST /v1/actions/<provider>.<action>``, ``GET /v1/schema``).
* :class:`DemoClient` answers from fixed, in-memory sample data so the UI can
  be designed and reviewed today. Everything it returns is fake.

Design rule: the base class :class:`ControlClient` implements every
task-level method (``install_app``, ``request_elevation`` ...) on top of just
three primitives -- :meth:`ControlClient.get_facts`,
:meth:`ControlClient.run_action` and :meth:`ControlClient.get_schema`. The
two implementations only differ in those primitives, so the mapping from UI
task to API call lives in exactly one place (see ``README.md`` for the table).

Some providers, actions and fields used here are NOT in CONTROL-API.md yet.
They are marked ``ASSUMED`` below and listed in the README so the API design
can adopt or reject them.
"""

from __future__ import annotations

import copy
import datetime as _dt
import http.client
import json
import os
import re
import socket
import urllib.parse

DEFAULT_SOCKET_PATH = "/run/eld/api.sock"
API_PREFIX = "/v1"
DEMO_ENV_VAR = "WORKPLACE_DEMO"
SOCKET_ENV_VAR = "WORKPLACE_SOCKET"

DEMO_BANNER_TEXT = "Demo data: the device management service (eld) is not running."

_NAME_RE = re.compile(r"^[a-z][a-z0-9-]*$")
_ACTION_RE = re.compile(r"^[a-z][a-z0-9-]*\.[a-z][a-z0-9-]*$")

# Limits used for client-side validation of JIT requests (PERMISSIONS.md section 4).
# The daemon must enforce the real limits; these only give early feedback.
MIN_REASON_LENGTH = 5
MAX_ELEVATION_MINUTES = 8 * 60


class ControlError(Exception):
    """An API call failed (HTTP error status or malformed answer)."""

    def __init__(self, message, status=None, code=None):
        super().__init__(message)
        self.status = status
        self.code = code


class ControlUnavailable(ControlError):
    """The daemon could not be reached at all (no socket, refused, timeout)."""


def validate_provider(name):
    if not isinstance(name, str) or not _NAME_RE.match(name):
        raise ValueError("invalid provider name: %r" % (name,))
    return name


def validate_action(name):
    if not isinstance(name, str) or not _ACTION_RE.match(name):
        raise ValueError("invalid action name (expected <provider>.<action>): %r" % (name,))
    return name


def validate_elevation_request(role, reason, duration_minutes, max_minutes=None):
    """Return a list of human-readable problems; empty means the request is OK."""
    problems = []
    if not role:
        problems.append("Choose the access you need.")
    if not reason or len(reason.strip()) < MIN_REASON_LENGTH:
        problems.append("Explain briefly why you need it (at least %d characters)." % MIN_REASON_LENGTH)
    limit = MAX_ELEVATION_MINUTES if max_minutes is None else min(max_minutes, MAX_ELEVATION_MINUTES)
    if not isinstance(duration_minutes, int) or duration_minutes <= 0:
        problems.append("Choose how long you need it.")
    elif duration_minutes > limit:
        problems.append("The longest allowed duration is %d minutes." % limit)
    return problems


class ControlClient:
    """Interface used by the UI. Subclasses implement the three primitives."""

    #: True only for :class:`DemoClient`. The UI shows a banner when set.
    is_demo = False

    #: Short text for the About page ("where does this data come from").
    source_description = "unknown"

    # ---- primitives -------------------------------------------------------

    def get_facts(self, provider):
        """``GET /v1/facts/<provider>`` -> dict of facts for one provider."""
        raise NotImplementedError

    def run_action(self, action, params=None):
        """``POST /v1/actions/<provider>.<action>`` -> dict describing the result."""
        raise NotImplementedError

    def get_schema(self):
        """``GET /v1/schema`` -> the published JSON Schema / OpenAPI document."""
        raise NotImplementedError

    # ---- Home / Status ----------------------------------------------------

    def get_compliance(self):
        """Overall state (green/amber/red) plus individual checks.

        Shape: ``{"state", "evaluated_at", "last_policy_sync", "policy":
        {"name", "version"}, "checks": [{"id", "title", "status"
        (pass|warn|fail|unknown), "detail", "fix": {"action", "params",
        "label"} | None}]}``
        """
        return self.get_facts("compliance")

    def evaluate_compliance(self):
        return self.run_action("compliance.evaluate")

    # ---- Apps -------------------------------------------------------------

    def list_catalog(self):
        """Allowed catalog for this user: ``{"bundles": [...], "apps": [...]}``.

        ASSUMED: CONTROL-API.md lists "installed apps" as an ``apps`` fact and
        the allowed catalog as an ``apps`` setting. We assume the ``apps``
        facts also expose the catalog as seen by the calling user.
        """
        facts = self.get_facts("apps")
        return {"bundles": facts.get("bundles", []), "apps": facts.get("catalog", [])}

    def install_app(self, app_id):
        return self.run_action("apps.install", {"id": app_id})

    def remove_app(self, app_id):
        return self.run_action("apps.remove", {"id": app_id})

    def request_app(self, app_id, reason):
        """ASSUMED action ``apps.request``: ask IT to approve an app."""
        return self.run_action("apps.request", {"id": app_id, "reason": reason})

    def get_default_apps(self):
        """ASSUMED fact ``desktop.default_apps``: ``{kind: {"current", "choices", "locked"}}``."""
        return self.get_facts("desktop").get("default_apps", {})

    def set_default_app(self, kind, app_id):
        """ASSUMED action ``desktop.set-default-app`` (within the catalog only)."""
        return self.run_action("desktop.set-default-app", {"kind": kind, "id": app_id})

    # ---- Updates ----------------------------------------------------------

    def get_updates(self):
        return self.get_facts("updates")

    def check_updates(self):
        return self.run_action("updates.check")

    def install_updates_now(self):
        return self.run_action("updates.install-now")

    def restart_now(self):
        return self.run_action("device.reboot")

    def defer_restart(self, hours):
        """ASSUMED action ``updates.defer`` ("Remind me"), bounded by maxDeferralDays."""
        return self.run_action("updates.defer", {"hours": int(hours)})

    # ---- Access (JIT elevation) --------------------------------------------

    def list_grants(self):
        """``roles`` facts for the calling user: roles, grants, requests, requestable roles."""
        return self.get_facts("roles")

    def request_elevation(self, role, reason, duration_minutes, ticket=None):
        """ASSUMED action ``roles.request-temporary`` (user side of roles.grant-temporary)."""
        problems = validate_elevation_request(role, reason, duration_minutes)
        if problems:
            raise ValueError(" ".join(problems))
        params = {"role": role, "reason": reason.strip(), "duration_minutes": duration_minutes}
        if ticket:
            params["ticket"] = ticket
        return self.run_action("roles.request-temporary", params)

    def revoke_grant(self, role):
        return self.run_action("roles.revoke", {"role": role})

    # ---- Devices ----------------------------------------------------------

    def get_peripherals(self):
        """ASSUMED provider ``devices``: usb policy + devices, printers, bluetooth."""
        return self.get_facts("devices")

    def approve_usb_device(self, device_id):
        """ASSUMED action ``usb.allow-device`` (only if policy allows user approval)."""
        return self.run_action("usb.allow-device", {"id": device_id})

    # ---- Help -------------------------------------------------------------

    def get_support_info(self):
        """ASSUMED provider ``support``: org name, contact channels, remote assist."""
        return self.get_facts("support")

    def collect_logs(self):
        return self.run_action("device.collect-logs")

    def open_ticket(self, summary, description, attach_logs=True):
        """ASSUMED action ``support.open-ticket``."""
        return self.run_action(
            "support.open-ticket",
            {"summary": summary, "description": description, "attach_logs": bool(attach_logs)},
        )

    def start_remote_assist(self):
        """ASSUMED action ``support.start-remote-assist`` (user-initiated, user must accept)."""
        return self.run_action("support.start-remote-assist")

    # ---- About ------------------------------------------------------------

    def get_device_info(self):
        return {"device": self.get_facts("device"), "os": self.get_facts("os")}

    def get_locked_keys(self):
        """ASSUMED fact ``desktop.locked_keys``: dconf paths locked by policy."""
        return list(self.get_facts("desktop").get("locked_keys", []))


# --------------------------------------------------------------------------
# REST over the Unix socket
# --------------------------------------------------------------------------


class UnixHTTPConnection(http.client.HTTPConnection):
    """``http.client`` connection that connects to a Unix domain socket."""

    def __init__(self, socket_path, timeout=10.0):
        super().__init__("localhost", timeout=timeout)
        self.socket_path = socket_path

    def connect(self):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            sock.connect(self.socket_path)
        except OSError:
            sock.close()
            raise
        self.sock = sock


class RestClient(ControlClient):
    """REST/JSON client for ``eld`` over ``/run/eld/api.sock``.

    Authentication is the caller's Unix peer credentials (SO_PEERCRED); no
    tokens are sent. One short-lived connection per request keeps it simple.
    """

    is_demo = False

    def __init__(self, socket_path=DEFAULT_SOCKET_PATH, timeout=10.0):
        self.socket_path = socket_path
        self.timeout = timeout
        self.source_description = "Device management service (eld) at %s" % socket_path

    def _request(self, method, path, body=None):
        headers = {"Accept": "application/json", "User-Agent": "workplace"}
        payload = None
        if body is not None:
            payload = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        conn = UnixHTTPConnection(self.socket_path, timeout=self.timeout)
        try:
            try:
                conn.request(method, path, body=payload, headers=headers)
                resp = conn.getresponse()
                raw = resp.read()
            except (OSError, http.client.HTTPException) as exc:
                raise ControlUnavailable(
                    "Cannot reach the device management service at %s: %s" % (self.socket_path, exc)
                ) from exc
        finally:
            conn.close()

        data = None
        if raw:
            try:
                data = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, ValueError) as exc:
                if 200 <= resp.status < 300:
                    raise ControlError("Malformed JSON from %s %s" % (method, path), status=resp.status) from exc
        if not 200 <= resp.status < 300:
            message, code = _error_message(data, resp)
            raise ControlError(message, status=resp.status, code=code)
        return data if data is not None else {}

    def get_facts(self, provider):
        validate_provider(provider)
        data = self._request("GET", "%s/facts/%s" % (API_PREFIX, urllib.parse.quote(provider)))
        # Accept both a bare fact object and one wrapped as {"<provider>": {...}}.
        if isinstance(data, dict) and set(data) == {provider} and isinstance(data[provider], dict):
            data = data[provider]
        if not isinstance(data, dict):
            raise ControlError("Unexpected facts payload for %s" % provider)
        return data

    def get_all_facts(self):
        return self._request("GET", "%s/facts" % API_PREFIX)

    def run_action(self, action, params=None):
        validate_action(action)
        data = self._request(
            "POST", "%s/actions/%s" % (API_PREFIX, urllib.parse.quote(action)), body=params or {}
        )
        if not isinstance(data, dict):
            raise ControlError("Unexpected action result for %s" % action)
        return data

    def get_schema(self):
        return self._request("GET", "%s/schema" % API_PREFIX)


def _error_message(data, resp):
    if isinstance(data, dict):
        err = data.get("error")
        if isinstance(err, dict):
            return str(err.get("message") or resp.reason), err.get("code")
        if isinstance(err, str):
            return err, None
        if "message" in data:
            return str(data["message"]), data.get("code")
    return "HTTP %d %s" % (resp.status, resp.reason), None


# --------------------------------------------------------------------------
# Demo data
# --------------------------------------------------------------------------


def _iso(dt):
    return dt.replace(microsecond=0).isoformat()


class DemoClient(ControlClient):
    """Fixed sample data. Everything here is fake and labelled as such.

    Actions mutate an in-memory copy so the UI feels responsive while
    designing (installing an app marks it installed, etc.). Nothing touches
    the system.
    """

    is_demo = True
    source_description = "Demo data (eld is not running; nothing is real)"

    def __init__(self, now=None):
        self._now = now or _dt.datetime.now(_dt.timezone.utc)
        self._facts = _demo_facts(self._now)
        self._counter = 1000
        self.action_log = []  # (action, params) tuples, handy for tests

    def _next_id(self, prefix):
        self._counter += 1
        return "%s-%d" % (prefix, self._counter)

    def get_facts(self, provider):
        validate_provider(provider)
        if provider not in self._facts:
            raise ControlError("No such provider: %s" % provider, status=404, code="not-found")
        return copy.deepcopy(self._facts[provider])

    def get_all_facts(self):
        return copy.deepcopy(self._facts)

    def get_schema(self):
        return {"demo": True, "providers": sorted(self._facts), "actions": sorted(_DEMO_ACTIONS)}

    def run_action(self, action, params=None):
        validate_action(action)
        params = dict(params or {})
        if action not in _DEMO_ACTIONS:
            raise ControlError("No such action: %s" % action, status=404, code="not-found")
        self.action_log.append((action, params))
        handler = getattr(self, "_do_" + action.replace(".", "_").replace("-", "_"), None)
        result = handler(params) if handler else {}
        out = {"action": action, "status": "completed", "demo": True}
        out.update(result)
        return out

    # -- handlers (only state changes worth showing in the UI) --

    def _find_app(self, app_id):
        for app in self._facts["apps"]["catalog"]:
            if app["id"] == app_id:
                return app
        raise ControlError("App is not in the catalog: %s" % app_id, status=404, code="not-found")

    def _do_apps_install(self, p):
        app = self._find_app(p.get("id"))
        if app["requires_approval"] and app.get("request_state") != "approved":
            raise ControlError("This app needs approval. Use Request instead.", status=403, code="approval-required")
        app["installed"] = True
        return {"message": "%s installed (demo)." % app["name"]}

    def _do_apps_remove(self, p):
        app = self._find_app(p.get("id"))
        if app.get("removable") is False:
            raise ControlError("%s is required by your organization." % app["name"], status=403, code="forbidden")
        app["installed"] = False
        return {"message": "%s removed (demo)." % app["name"]}

    def _do_apps_request(self, p):
        app = self._find_app(p.get("id"))
        app["request_state"] = "pending"
        req = self._next_id("REQ")
        return {"status": "pending-approval", "request_id": req,
                "message": "Request %s sent to IT for %s (demo)." % (req, app["name"])}

    def _do_desktop_set_default_app(self, p):
        kinds = self._facts["desktop"]["default_apps"]
        entry = kinds.get(p.get("kind"))
        if entry is None:
            raise ControlError("Unknown default app kind", status=400, code="invalid")
        if entry.get("locked"):
            raise ControlError("Managed by your organization.", status=403, code="locked")
        if p.get("id") not in entry["choices"]:
            raise ControlError("That app is not allowed for this purpose.", status=400, code="invalid")
        entry["current"] = p["id"]
        return {"message": "Default updated (demo)."}

    def _do_updates_install_now(self, p):
        upd = self._facts["updates"]
        upd["pending"] = []
        upd["reboot_required"] = True
        upd["last_success"] = _iso(self._now)
        return {"message": "Updates installed (demo). Restart to finish."}

    def _do_updates_defer(self, p):
        upd = self._facts["updates"]
        hours = int(p.get("hours", 1))
        if hours <= 0 or hours > upd["deferral_hours_left"]:
            raise ControlError("You can defer by at most %d more hours." % upd["deferral_hours_left"],
                               status=400, code="deferral-limit")
        upd["deferral_hours_left"] -= hours
        upd["deferred_until"] = _iso(self._now + _dt.timedelta(hours=hours))
        return {"message": "We will remind you in %d hour(s) (demo)." % hours}

    def _do_device_reboot(self, p):
        return {"status": "scheduled", "message": "A real device would restart now. Demo: nothing happens."}

    def _do_roles_request_temporary(self, p):
        roles = self._facts["roles"]
        req = {"id": self._next_id("JIT"), "role": p["role"], "reason": p.get("reason", ""),
               "duration_minutes": p.get("duration_minutes"), "ticket": p.get("ticket"),
               "state": "pending", "submitted_at": _iso(self._now)}
        roles["requests"].append(req)
        return {"status": "pending-approval", "request_id": req["id"],
                "message": "Request %s sent to your approver (demo)." % req["id"]}

    def _do_roles_revoke(self, p):
        roles = self._facts["roles"]
        roles["grants"] = [g for g in roles["grants"] if g["role"] != p.get("role")]
        if p.get("role") in roles["effective_roles"] and p.get("role") != "user":
            roles["effective_roles"].remove(p["role"])
        return {"message": "Access ended (demo)."}

    def _do_usb_allow_device(self, p):
        devs = self._facts["devices"]
        if not devs["usb_policy"]["user_approval"]:
            raise ControlError("Your organization does not allow approving USB devices here.",
                               status=403, code="forbidden")
        for dev in devs["usb"]:
            if dev["id"] == p.get("id"):
                dev["state"] = "allowed"
                return {"message": "%s allowed (demo)." % dev["name"]}
        raise ControlError("No such device", status=404, code="not-found")

    def _do_device_collect_logs(self, p):
        stamp = self._now.strftime("%Y%m%dT%H%M%SZ")
        return {"bundle": "/var/lib/eld/diagnostics/demo-%s.tar.zst" % stamp, "size_bytes": 2_481_152,
                "message": "Diagnostics collected (demo file, not created)."}

    def _do_support_open_ticket(self, p):
        if not (p.get("summary") or "").strip():
            raise ControlError("Add a short summary.", status=400, code="invalid")
        ticket = self._next_id("DEMO-INC")
        return {"ticket": ticket, "message": "Ticket %s created (demo, nobody receives it)." % ticket}

    def _do_support_start_remote_assist(self, p):
        return {"status": "waiting-for-technician", "code": "482 913",
                "message": "Read this code to IT. You will be asked to accept before they can see your screen (demo)."}

    def _do_compliance_evaluate(self, p):
        self._facts["compliance"]["evaluated_at"] = _iso(self._now)
        return {"message": "Checked again (demo)."}


_DEMO_ACTIONS = frozenset({
    "apps.install", "apps.remove", "apps.repair", "apps.request",
    "compliance.evaluate",
    "desktop.set-default-app",
    "device.collect-logs", "device.reboot",
    "identity.resync",
    "roles.request-temporary", "roles.revoke",
    "support.open-ticket", "support.start-remote-assist",
    "updates.check", "updates.defer", "updates.install-now",
    "usb.allow-device",
})


def _app(app_id, name, summary, category, bundle, source, license_kind, license, *,
         installed=False, requires_approval=False, removable=True):
    return {
        "id": app_id, "name": name, "summary": summary, "category": category,
        "bundle": bundle, "source": source, "license_kind": license_kind, "license": license,
        "installed": installed, "requires_approval": requires_approval,
        "removable": removable, "request_state": None,
    }


def _demo_catalog():
    # Illustrative only: the real seed list (CURATED-APPS.md section 5) is still empty.
    # It mixes open-source and proprietary/vendor options on purpose.
    return [
        # Browsers
        _app("org.mozilla.firefox", "Firefox ESR", "Web browser (extended support release)",
             "browser", "base", "flatpak:curated", "open-source", "MPL-2.0", installed=True, removable=False),
        _app("org.chromium.Chromium", "Chromium", "Open-source web browser",
             "browser", "base", "flatpak:curated", "open-source", "BSD-3-Clause"),
        _app("com.microsoft.Edge", "Microsoft Edge", "Web browser with Microsoft Entra sign-in",
             "browser", "base", "vendor", "proprietary", "Microsoft EULA", installed=True),
        _app("com.google.Chrome", "Google Chrome", "Web browser",
             "browser", "base", "vendor", "proprietary", "Google ToS"),
        # Office
        _app("org.libreoffice.LibreOffice", "LibreOffice", "Documents, spreadsheets and presentations",
             "office", "office", "flatpak:curated", "open-source", "MPL-2.0", installed=True),
        _app("org.onlyoffice.desktopeditors", "ONLYOFFICE Desktop Editors",
             "Office suite with strong .docx/.xlsx/.pptx compatibility",
             "office", "office", "flatpak:curated", "open-source", "AGPL-3.0"),
        _app("pwa.microsoft365", "Microsoft 365 (web)", "Word, Excel, PowerPoint and Outlook as web apps",
             "office", "office", "pwa", "proprietary", "Microsoft subscription", installed=True),
        _app("pwa.google-workspace", "Google Workspace (web)", "Docs, Sheets and Slides as web apps",
             "office", "office", "pwa", "proprietary", "Google subscription"),
        # Mail and calendar
        _app("org.mozilla.Thunderbird", "Thunderbird", "Mail and calendar",
             "mail", "office", "flatpak:curated", "open-source", "MPL-2.0"),
        _app("org.gnome.Evolution", "Evolution (with EWS)", "Mail, calendar and contacts for Exchange",
             "mail", "office", "native", "open-source", "LGPL-2.0+", installed=True),
        # Collaboration
        _app("pwa.teams", "Microsoft Teams (web)", "Chat and meetings", "collaboration", "collaboration",
             "pwa", "proprietary", "Microsoft subscription"),
        _app("us.zoom.Zoom", "Zoom", "Video meetings", "collaboration", "collaboration",
             "vendor", "proprietary", "Zoom ToS"),
        _app("com.slack.Slack", "Slack", "Team chat", "collaboration", "collaboration",
             "vendor", "proprietary", "Slack ToS", requires_approval=True),
        _app("org.jitsi.jitsi-meet", "Jitsi Meet", "Open-source video meetings", "collaboration",
             "collaboration", "flatpak:curated", "open-source", "Apache-2.0"),
        # Development
        _app("com.visualstudio.code", "Visual Studio Code", "Code editor", "development", "dev",
             "vendor", "proprietary", "Microsoft EULA", requires_approval=True),
        _app("com.vscodium.codium", "VSCodium", "Code editor built from open-source VS Code sources",
             "development", "dev", "flatpak:curated", "open-source", "MIT"),
        _app("com.github.containers.Toolbox", "Toolbox", "Containers for development tools",
             "development", "dev", "native", "open-source", "Apache-2.0", requires_approval=True),
        # Design and media
        _app("org.gimp.GIMP", "GIMP", "Image editor", "design", "design", "flatpak:curated",
             "open-source", "GPL-3.0"),
        _app("org.inkscape.Inkscape", "Inkscape", "Vector graphics", "design", "design",
             "flatpak:curated", "open-source", "GPL-2.0"),
        # Security tools (restricted)
        _app("org.keepassxc.KeePassXC", "KeePassXC", "Password manager", "security", "security-tools",
             "flatpak:curated", "open-source", "GPL-3.0", requires_approval=True),
        _app("org.wireshark.Wireshark", "Wireshark", "Network protocol analyzer", "security",
             "security-tools", "flatpak:curated", "open-source", "GPL-2.0", requires_approval=True),
    ]


def _demo_facts(now):
    ago = lambda **kw: _iso(now - _dt.timedelta(**kw))  # noqa: E731
    ahead = lambda **kw: _iso(now + _dt.timedelta(**kw))  # noqa: E731
    return {
        "compliance": {
            "state": "amber",
            "evaluated_at": ago(minutes=12),
            "last_policy_sync": ago(minutes=12),
            "policy": {"name": "demo-laptops", "version": "2026.10.3"},
            "checks": [
                {"id": "encryption", "title": "Disk encryption", "status": "pass",
                 "detail": "The system disk is encrypted (TPM + PIN).", "fix": None},
                {"id": "updates", "title": "Up to date", "status": "warn",
                 "detail": "3 updates are ready. A restart is needed.",
                 "fix": {"action": "updates.install-now", "params": {}, "label": "Install now"}},
                {"id": "secure-boot", "title": "Secure Boot", "status": "pass",
                 "detail": "Secure Boot is on.", "fix": None},
                {"id": "edr", "title": "Endpoint protection", "status": "fail",
                 "detail": "The endpoint protection agent is not running.",
                 "fix": {"action": "apps.repair", "params": {"id": "edr-agent"}, "label": "Repair"}},
                {"id": "firewall", "title": "Firewall", "status": "pass",
                 "detail": "Firewall is on with your organization's rules.", "fix": None},
                {"id": "policy-sync", "title": "Policy sync", "status": "pass",
                 "detail": "Last synced 12 minutes ago.",
                 "fix": {"action": "identity.resync", "params": {}, "label": "Sync now"}},
            ],
        },
        "apps": {
            "bundles": [
                {"id": "core", "name": "Core", "enabled": True, "required": True,
                 "description": "What the OS needs to be managed and secure"},
                {"id": "base", "name": "Base", "enabled": True, "required": False,
                 "description": "Browsers, PDF and image viewers, printing"},
                {"id": "office", "name": "Office", "enabled": True, "required": False,
                 "description": "Office suites, mail and calendar"},
                {"id": "collaboration", "name": "Collaboration", "enabled": False, "required": False,
                 "description": "Meetings and chat"},
                {"id": "dev", "name": "Development", "enabled": False, "required": False,
                 "description": "Editors and containers (power-user role)"},
            ],
            "catalog": _demo_catalog(),
        },
        "desktop": {
            "session_type": "wayland",
            "theme": "default",
            "locked_keys": [
                "/org/gnome/desktop/screensaver/lock-enabled",
                "/org/gnome/desktop/screensaver/lock-delay",
                "/org/gnome/desktop/session/idle-delay",
                "/org/gnome/desktop/lockdown/disable-lock-screen",
                "/org/gnome/shell/enabled-extensions",
                "/org/gnome/system/proxy/mode",
            ],
            "default_apps": {
                "browser": {"current": "org.mozilla.firefox", "locked": False,
                            "choices": ["org.mozilla.firefox", "org.chromium.Chromium",
                                        "com.microsoft.Edge", "com.google.Chrome"]},
                "office": {"current": "org.libreoffice.LibreOffice", "locked": False,
                           "choices": ["org.libreoffice.LibreOffice", "org.onlyoffice.desktopeditors",
                                       "pwa.microsoft365"]},
                "mail": {"current": "org.gnome.Evolution", "locked": True,
                         "choices": ["org.gnome.Evolution", "org.mozilla.Thunderbird"]},
            },
        },
        "updates": {
            "pending": [
                {"name": "kernel", "from": "6.8.0-45", "to": "6.8.0-47", "kind": "security"},
                {"name": "openssl", "from": "3.0.13-0ubuntu3.3", "to": "3.0.13-0ubuntu3.4", "kind": "security"},
                {"name": "Firefox ESR", "from": "128.3", "to": "128.4", "kind": "app"},
            ],
            "reboot_required": True,
            "last_success": ago(days=6),
            "ring": "broad",
            "maintenance_window": "Mon-Fri 12:00-13:00",
            "next_window": ahead(hours=20),
            "max_deferral_days": 7,
            "deferral_hours_left": 72,
            "deferred_until": None,
        },
        "roles": {
            "user": "demo.user@example.org",
            "effective_roles": ["user"],
            "grants": [],
            "requests": [],
            "requestable_roles": [
                {"id": "local-admin", "name": "Temporary administrator",
                 "description": "Install software and change system settings",
                 "max_minutes": 60, "approval": "helpdesk"},
                {"id": "power-user", "name": "Developer containers",
                 "description": "Use Toolbox/Distrobox for development tools",
                 "max_minutes": 480, "approval": "auto"},
            ],
        },
        "devices": {
            "usb_policy": {"storage": "block", "user_approval": True,
                           "note": "USB storage is blocked unless you approve a specific device."},
            "usb": [
                {"id": "usb-1", "name": "Logitech USB Receiver", "class": "input",
                 "vendor_id": "046d", "product_id": "c52b", "state": "allowed"},
                {"id": "usb-2", "name": "SanDisk Ultra (32 GB)", "class": "storage",
                 "vendor_id": "0781", "product_id": "5581", "state": "blocked"},
            ],
            "printers": [
                {"name": "Office-3F-Color", "state": "idle", "default": True},
                {"name": "Office-3F-Mono", "state": "offline", "default": False},
            ],
            "bluetooth": {"enabled": True, "devices": [
                {"name": "Demo Headset", "connected": True},
            ]},
        },
        "support": {
            "org_name": "Example Org IT (demo)",
            "email": "it-help@example.org",
            "phone": "+1 555 0100",
            "hours": "Mon-Fri 08:00-18:00",
            "portal_url": "https://help.example.org",
            "remote_assist_available": True,
        },
        "device": {
            "name": "DEMO-LT-0042",
            "serial": "DEMO0000SERIAL",
            "model": "Demo Laptop 14",
            "tpm_present": True,
            "firmware": "1.12.0",
            "enrollment": {
                "state": "enrolled",
                "managed_by": "Example Org IT (demo)",
                "service": "MDM (demo, not connected)",
                "enrolled_at": ago(days=40),
            },
            "privacy": {
                "can_see": [
                    "Device name, model and serial number",
                    "Operating system version and installed apps",
                    "Security status: encryption, updates, firewall, Secure Boot",
                    "Who signed in to this device and when",
                ],
                "cannot_see": [
                    "Your files, documents and photos",
                    "Your browsing history",
                    "Your personal email and messages",
                    "Your screen, unless you accept a remote-assist session",
                ],
            },
        },
        "os": {
            "distro": "enterprise-linux (demo)",
            "version": "0.0-demo",
            "image_id": "demo-image",
            "build_hash": "0000000",
            "kernel": "6.8.0-45-generic",
        },
    }


# --------------------------------------------------------------------------
# Choosing a client
# --------------------------------------------------------------------------


def _truthy(value):
    return str(value).strip().lower() in ("1", "true", "yes", "on")


def select_client(demo=False, socket_path=None, environ=None):
    """Pick the client the app should use.

    Returns ``(client, demo_reason)``. ``demo_reason`` is ``None`` for the
    real client, otherwise a short explanation shown next to the banner.

    Order: ``--demo`` flag, then ``WORKPLACE_DEMO=1``, then whether the socket
    exists. A socket that exists but refuses connections still yields a
    :class:`RestClient`; the UI reports those errors per call.
    """
    environ = os.environ if environ is None else environ
    path = socket_path or environ.get(SOCKET_ENV_VAR) or DEFAULT_SOCKET_PATH
    if demo:
        return DemoClient(), "Started with --demo."
    if _truthy(environ.get(DEMO_ENV_VAR, "")):
        return DemoClient(), "%s is set." % DEMO_ENV_VAR
    if not os.path.exists(path):
        return DemoClient(), "No socket at %s." % path
    return RestClient(path), None
