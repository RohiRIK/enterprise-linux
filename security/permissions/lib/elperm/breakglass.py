"""LAPS-style break-glass account management (PERMISSIONS.md sections 2 and 5).

Rotation order is escrow-first: the new password is handed to the escrow hook
(policy breakGlass.escrowCommand, e.g. an MDM agent CLI) on stdin BEFORE it is
set with chpasswd. If escrow fails nothing changes. If chpasswd fails after a
successful escrow, the escrow holds a password that is not in use yet; escrow
backends must therefore keep history (as Windows LAPS does) and the event
breakglass.rotation_failed is raised at alert severity.

The password is never printed, logged or stored locally, except to stdout
when --reveal-to-stdout-for-escrow-pipe is given AND stdout is not a terminal.

Settings are read from /etc/el/roles/breakglass.json (rendered, no secrets),
not from the signed cache, so break-glass works even when the cache is
expired or invalid.
"""

from __future__ import annotations

import json
import secrets
import string

from .events import emitter_for
from .util import (BREAKGLASS_CONF, BREAKGLASS_STATE, Context, ElPermError, StateLock,
                   atomic_write, iso, pretty_json, read_json)

DEFAULTS = {"account": "elbreakglass", "passwordLength": 24, "escrowCommand": None,
            "rotateAfterUseMinutes": 60, "rotateEveryDays": 30}

# No ambiguous characters (0/O, 1/l/I) and nothing that breaks chpasswd's "user:pass" line.
ALPHABET = "".join(c for c in string.ascii_letters + string.digits + "!#%+-.=@^_~"
                   if c not in "0O1lI")


def generate_password(length: int) -> str:
    """Random password with at least one char of each class."""
    classes = [set(string.ascii_lowercase), set(string.ascii_uppercase), set(string.digits),
               set("!#%+-.=@^_~")]
    while True:
        pw = "".join(secrets.choice(ALPHABET) for _ in range(length))
        if all(any(c in cls for c in pw) for cls in classes):
            return pw


class BreakGlass:
    def __init__(self, ctx: Context, settings: dict | None = None):
        self.ctx = ctx
        self.emit = emitter_for(ctx)
        conf = read_json(ctx.path(BREAKGLASS_CONF), default={}) or {}
        self.settings = {**DEFAULTS, **conf, **(settings or {})}

    @property
    def account(self) -> str:
        return self.settings["account"]

    def _state(self) -> dict:
        return read_json(self.ctx.path(BREAKGLASS_STATE), default=None) or {
            "account": self.account, "last_rotated_at": None, "generation": 0,
            "last_used_at": None, "rotate_due_at": None}

    def _save(self, st: dict):
        atomic_write(self.ctx.path(BREAKGLASS_STATE), pretty_json(st), 0o600)

    # ------------------------------------------------------------- rotation
    def is_due(self, st: dict | None = None) -> tuple[bool, str]:
        st = st or self._state()
        now = self.ctx.now()
        if st.get("last_rotated_at") is None:
            return True, "never rotated"
        if st.get("rotate_due_at") and now >= st["rotate_due_at"]:
            return True, "used; rotation scheduled"
        if now >= st["last_rotated_at"] + self.settings["rotateEveryDays"] * 86400:
            return True, "periodic rotation"
        return False, ""

    def rotate(self, if_due: bool = False, reveal_stream=None) -> dict:
        """Rotate the password. `reveal_stream` (a writable, non-TTY stream) is
        the only way the password leaves this process besides the escrow hook."""
        with StateLock(self.ctx):
            st = self._state()
            due, why = self.is_due(st)
            if if_due and not due:
                return {"rotated": False, "reason": "not due"}
            escrow = self.settings.get("escrowCommand")
            if not escrow and reveal_stream is None:
                raise ElPermError("no breakGlass.escrowCommand configured and no "
                                  "--reveal-to-stdout-for-escrow-pipe: refusing to rotate "
                                  "(the new password would be lost)")
            if not self.ctx.user_exists(self.account):
                raise ElPermError(f"break-glass account {self.account!r} does not exist "
                                  "(create it in the image; see README)")
            password = generate_password(int(self.settings["passwordLength"]))
            generation = int(st.get("generation") or 0) + 1
            now = int(self.ctx.now())

            if escrow:
                payload = json.dumps({"account": self.account, "password": password,
                                      "generation": generation, "rotated_at": iso(now)})
                res = self.ctx.run(list(escrow), input=(payload + "\n").encode())
                if res.returncode != 0:
                    self.emit("breakglass.rotation_failed", user=self.account, stage="escrow",
                              reason=f"escrow hook exit {res.returncode}")
                    raise ElPermError(f"escrow hook failed (exit {res.returncode}); password unchanged")
            if reveal_stream is not None:
                reveal_stream.write(password + "\n")
                reveal_stream.flush()

            argv = ["chpasswd"]
            if not self.ctx.is_real_root:
                argv += ["-R", str(self.ctx.root)]
            res = self.ctx.run(argv, input=f"{self.account}:{password}\n".encode())
            del password
            if res.returncode != 0:
                self.emit("breakglass.rotation_failed", user=self.account, stage="chpasswd",
                          reason=f"chpasswd exit {res.returncode}; escrow holds an unused password")
                raise ElPermError("chpasswd failed after escrow; old password still active")
            st.update({"account": self.account, "last_rotated_at": now, "generation": generation,
                       "rotate_due_at": None})
            self._save(st)
        self.emit("breakglass.rotated", user=self.account, generation=generation,
                  reason=why or "manual")
        return {"rotated": True, "generation": generation, "reason": why or "manual"}

    # ------------------------------------------------------------------ use
    def mark_used(self, source: str = "manual", **details) -> dict:
        now = int(self.ctx.now())
        with StateLock(self.ctx):
            st = self._state()
            st["last_used_at"] = now
            due = now + int(self.settings["rotateAfterUseMinutes"]) * 60
            if not st.get("rotate_due_at") or st["rotate_due_at"] > due:
                st["rotate_due_at"] = due
            self._save(st)
        self.emit("breakglass.used", severity="crit", user=self.account, source=source,
                  rotate_due_at=iso(st["rotate_due_at"]), **details)
        return {"used": True, "rotate_due_at": iso(st["rotate_due_at"])}

    def pam_hook(self, env: dict) -> dict | None:
        """Called from pam_exec. Emits breakglass.used when PAM_USER is the account."""
        if env.get("PAM_USER") != self.account:
            return None
        if env.get("PAM_TYPE") not in ("open_session", "auth", "account"):
            return None
        return self.mark_used(source="pam", service=env.get("PAM_SERVICE"),
                              tty=env.get("PAM_TTY"), rhost=env.get("PAM_RHOST"),
                              ruser=env.get("PAM_RUSER"), pam_type=env.get("PAM_TYPE"))

    def status(self) -> dict:
        st = self._state()
        due, why = self.is_due(st)
        out = {k: (iso(v) if k.endswith("_at") and v else v) for k, v in st.items()}
        out.update({"rotation_due": due, "due_reason": why,
                    "escrow_configured": bool(self.settings.get("escrowCommand"))})
        return out
