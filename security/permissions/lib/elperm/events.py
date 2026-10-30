"""Structured audit events (PERMISSIONS.md section 6).

Each event is a flat JSON object {"event": "roles.granted", "ts": ..., ...}.
Delivery:
  1. journald via `logger --journald` (structured fields, stable MESSAGE_ID),
  2. fallback `systemd-cat -t el-perm -p <prio>` (JSON as MESSAGE),
  3. fallback stderr.
Optionally also printed to stdout (--json) for the calling agent.
"""

from __future__ import annotations

import json
import socket
import sys
import uuid

from .util import iso

# Stable 128-bit MESSAGE_IDs, derived once from the event name. Never change a
# published value; SIEM rules key on them.
_NS = uuid.UUID("6c1e7a0e-2f0b-4c64-9b8e-5e1d5a1f7c11")


def message_id(event: str) -> str:
    return uuid.uuid5(_NS, event).hex


# syslog priorities
PRIO = {"emerg": 0, "alert": 1, "crit": 2, "err": 3, "warning": 4, "notice": 5, "info": 6, "debug": 7}

DEFAULT_SEVERITY = {
    "roles.granted": "notice",
    "roles.revoked": "notice",
    "roles.expired": "notice",
    "roles.requested": "info",
    "roles.denied": "warning",
    "roles.rendered": "info",
    "roles.degraded": "warning",
    "roles.drift": "warning",
    "roles.cache_invalid": "err",
    "breakglass.used": "crit",
    "breakglass.rotated": "notice",
    "breakglass.rotation_failed": "alert",
}


class Emitter:
    """Default event sink. `run` and `which` come from the Context."""

    def __init__(self, ctx, to_stdout: bool = False, identifier: str = "el-perm"):
        self.ctx = ctx
        self.to_stdout = to_stdout
        self.identifier = identifier
        self.sent: list[dict] = []

    def __call__(self, event: str, severity: str | None = None, **fields) -> dict:
        severity = severity or DEFAULT_SEVERITY.get(event, "info")
        record = {"event": event, "ts": iso(self.ctx.now()), "severity": severity,
                  "host": socket.gethostname(), **fields}
        self.sent.append(record)
        line = json.dumps(record, sort_keys=True)
        if self.to_stdout:
            print(line, flush=True)
        self._journal(event, severity, record, line)
        return record

    def _journal(self, event, severity, record, line):
        prio = str(PRIO[severity])
        logger = self.ctx.which("logger")
        if logger:
            fields = [
                f"MESSAGE={event}: {line}",
                f"MESSAGE_ID={message_id(event)}",
                f"PRIORITY={prio}",
                f"SYSLOG_IDENTIFIER={self.identifier}",
                f"EL_EVENT={event}",
                f"EL_DATA={line}",
            ]
            for key in ("user", "role", "grant_id", "reason", "expires_at"):
                if key in record and record[key] is not None:
                    val = str(record[key]).replace("\n", " ")
                    fields.append(f"EL_{key.upper()}={val}")
            res = self.ctx.run([logger, "--journald"], input=("\n".join(fields) + "\n").encode())
            if res.returncode == 0:
                return
        syscat = self.ctx.which("systemd-cat")
        if syscat:
            res = self.ctx.run([syscat, "-t", self.identifier, "-p", prio],
                               input=(line + "\n").encode())
            if res.returncode == 0:
                return
        print(f"{self.identifier}: {line}", file=sys.stderr)


class MemoryEmitter:
    """Test sink: records events, sends nothing."""

    def __init__(self):
        self.sent: list[dict] = []

    def __call__(self, event: str, severity: str | None = None, **fields) -> dict:
        rec = {"event": event, "severity": severity or DEFAULT_SEVERITY.get(event, "info"), **fields}
        self.sent.append(rec)
        return rec

    def names(self) -> list[str]:
        return [e["event"] for e in self.sent]


def emitter_for(ctx, to_stdout: bool = False):
    if ctx.emit is None:
        ctx.emit = Emitter(ctx, to_stdout=to_stdout)
    return ctx.emit
