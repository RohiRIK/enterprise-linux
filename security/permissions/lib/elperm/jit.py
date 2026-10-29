"""Just-in-time elevation (PERMISSIONS.md section 4).

A grant is three things, created and removed together under a state lock:
  * /etc/sudoers.d/60-el-jit-<user>            full grant (jit role's sudo spec)
    /etc/sudoers.d/60-el-jit-<user>-cmd-<id>   command-scoped grant (exact command)
  * an entry in /etc/polkit-1/rules.d/39-el-jit.rules (full grants only),
    which embeds the expiry and stops matching after it even if no timer runs
  * a record in /var/lib/el/roles/grants.json

Expiry is enforced by: el-jit-expire.timer (every minute), the pam_exec
session-close hook (revoke on logout), sudo's NOTAFTER (classic sudo only;
sudo-rs does not support it) and the polkit rule's own clock check.
"""

from __future__ import annotations

import fnmatch
import os
import re
import secrets

from .cache import load_cache
from .events import emitter_for
from .policy import Policy, validate_policy
from .render import cmnd_spec, detect_sudo_impl, user_list, visudo_validator
from .util import (GRANTS, POLKIT_JIT, SUDOERS_JIT_PREFIX, Context, ElPermError, StateLock,
                   atomic_write, check_user, format_duration, iso, parse_duration, pretty_json,
                   read_json, remove_file, safe_file_token, sudoers_timestamp)

SAFE_COMMAND_RE = re.compile(r"^/[^\x00-\x1f,:=\\#*?\[\]!]+$")


class JitDenied(ElPermError):
    exit_code = 5


class Jit:
    def __init__(self, ctx: Context, policy: Policy | None = None):
        self.ctx = ctx
        self.emit = emitter_for(ctx)
        self._policy = policy

    # ---------------------------------------------------------------- policy
    def policy(self, require_valid: bool = True) -> Policy:
        if self._policy is not None:
            return self._policy
        status = load_cache(self.ctx)
        if status.state == "valid" or (status.state == "expired" and not require_valid):
            self._policy = validate_policy(status.policy)
            return self._policy
        raise JitDenied(f"elevation unavailable: role cache is {status.state} ({status.reason}); "
                        "sync the device or use break-glass")

    def cache_state(self) -> str:
        return load_cache(self.ctx).state

    # ----------------------------------------------------------------- state
    def _load(self) -> dict:
        return read_json(self.ctx.path(GRANTS), default=None) or {"version": 1, "grants": [], "requests": []}

    def _save(self, state: dict):
        atomic_write(self.ctx.path(GRANTS), pretty_json(state), 0o600)

    # ------------------------------------------------------------ validation
    def _check_eligible(self, policy: Policy, user: str):
        check_user(user)
        if not self.ctx.user_exists(user):
            raise JitDenied(f"user {user!r} does not resolve via NSS (identity module offline or unknown user)")
        deny = set(policy.posix(policy.login["deny"]))
        hit = deny & set(self.ctx.groups_of(user))
        if hit:
            self.emit("roles.denied", user=user, reason=f"member of login-deny group(s) {sorted(hit)}")
            raise JitDenied(f"{user} is in a login-deny group ({', '.join(sorted(hit))}); deny overrides allow")
        if user == policy.breakglass["account"]:
            raise JitDenied("the break-glass account cannot receive JIT grants")

    def _check_duration(self, policy: Policy, seconds: int | None) -> int:
        seconds = seconds or policy.default_jit_seconds
        if seconds > policy.max_jit_seconds:
            raise JitDenied(f"requested {format_duration(seconds)} exceeds jit.maxDuration "
                            f"{policy.jit['maxDuration']}")
        return seconds

    def _check_commands(self, policy: Policy, commands: list[str]) -> list[str]:
        out = []
        for cmd in commands:
            cmd = " ".join(cmd.split())
            if not SAFE_COMMAND_RE.match(cmd):
                raise JitDenied(f"command {cmd!r} must be an absolute path without sudoers "
                                "special characters or wildcards")
            if not any(fnmatch.fnmatchcase(cmd, pat) for pat in policy.jit["commandAllowlist"]):
                raise JitDenied(f"command {cmd!r} is not in jit.commandAllowlist")
            out.append(cmd)
        return out

    def _clean_reason(self, policy: Policy, reason: str | None) -> str:
        reason = " ".join((reason or "").split())[:200]
        if policy.jit["requireReason"] and not reason:
            raise JitDenied("a --reason is required by policy")
        return reason

    def _caller_may_approve(self, policy: Policy, approver: str, subject_user: str | None):
        if approver == "root":
            return
        if subject_user is not None and approver == subject_user:
            raise JitDenied("self-approval is not allowed")
        groups = set(self.ctx.groups_of(approver))
        allowed = set()
        for rname in policy.jit["approver"]["approverRoles"]:
            role = policy.roles.get(rname)
            if role and role["enabled"]:
                allowed |= set(policy.posix(role["groups"]))
        if not (groups & allowed):
            raise JitDenied(f"{approver} is not in an approver role "
                            f"({', '.join(policy.jit['approver']['approverRoles'])})")

    # --------------------------------------------------------------- actions
    def request(self, user: str, reason: str | None, seconds: int | None = None,
                commands: list[str] | None = None, ticket: str | None = None) -> dict:
        policy = self.policy()
        if not policy.jit["enabled"]:
            raise JitDenied("JIT elevation is disabled by policy")
        self._check_eligible(policy, user)
        seconds = self._check_duration(policy, seconds)
        commands = self._check_commands(policy, commands or [])
        reason = self._clean_reason(policy, reason)
        ap = policy.jit["approver"]
        mode = ap["mode"]
        self.emit("roles.requested", user=user, role=policy.jit["role"], reason=reason,
                  duration=format_duration(seconds), commands=commands, approver_mode=mode)

        if mode == "auto":
            auto = set(policy.posix(ap["autoApproveGroups"]))
            if auto & set(self.ctx.groups_of(user)):
                return self.grant(user, seconds, reason, commands, approver="auto", ticket=ticket)
            # not auto-eligible: fall through to a pending request for helpdesk
        elif mode == "ticket":
            if not ticket or not re.fullmatch(ap["ticketPattern"], ticket):
                self.emit("roles.denied", user=user, reason="missing or malformed ticket")
                raise JitDenied(f"approver mode 'ticket' needs --ticket matching {ap['ticketPattern']}")
            if ap["ticketVerifyCommand"]:
                res = self.ctx.run([*ap["ticketVerifyCommand"], ticket, user])
                if res.returncode != 0:
                    self.emit("roles.denied", user=user, reason=f"ticket {ticket} rejected by verifier")
                    raise JitDenied(f"ticket {ticket} rejected by ticketVerifyCommand")
            return self.grant(user, seconds, reason, commands, approver=f"ticket:{ticket}", ticket=ticket)

        with StateLock(self.ctx):
            state = self._load()
            req = {"id": secrets.token_hex(4), "user": user, "reason": reason,
                   "seconds": seconds, "commands": commands, "ticket": ticket,
                   "requested_at": int(self.ctx.now()), "status": "pending"}
            state["requests"].append(req)
            self._save(state)
        return {"status": "pending", "request": req}

    def approve(self, request_id: str, approver: str) -> dict:
        policy = self.policy()
        with StateLock(self.ctx):
            state = self._load()
            req = next((r for r in state["requests"] if r["id"] == request_id and r["status"] == "pending"), None)
            if not req:
                raise ElPermError(f"no pending request {request_id}")
        self._caller_may_approve(policy, approver, req["user"])
        result = self.grant(req["user"], req["seconds"], req["reason"], req["commands"],
                            approver=approver, ticket=req.get("ticket"), request_id=request_id)
        with StateLock(self.ctx):
            state = self._load()
            for r in state["requests"]:
                if r["id"] == request_id:
                    r["status"], r["decided_by"] = "approved", approver
            self._save(state)
        return result

    def deny(self, request_id: str, approver: str) -> dict:
        policy = self.policy(require_valid=False)
        with StateLock(self.ctx):
            state = self._load()
            req = next((r for r in state["requests"] if r["id"] == request_id and r["status"] == "pending"), None)
            if not req:
                raise ElPermError(f"no pending request {request_id}")
            self._caller_may_approve(policy, approver, None)
            req["status"], req["decided_by"] = "denied", approver
            self._save(state)
        self.emit("roles.denied", user=req["user"], reason=f"request {request_id} denied by {approver}")
        return {"status": "denied", "request": req}

    def grant(self, user: str, seconds: int | None, reason: str | None,
              commands: list[str] | None = None, approver: str = "root",
              ticket: str | None = None, request_id: str | None = None) -> dict:
        policy = self.policy()
        if not policy.jit["enabled"]:
            raise JitDenied("JIT elevation is disabled by policy")
        self._check_eligible(policy, user)
        seconds = self._check_duration(policy, seconds)
        commands = self._check_commands(policy, commands or [])
        reason = self._clean_reason(policy, reason)
        if approver not in ("root", "auto") and not approver.startswith("ticket:"):
            self._caller_may_approve(policy, approver, user)
        role = policy.roles[policy.jit["role"]]
        now = int(self.ctx.now())
        expires = now + seconds
        gid = secrets.token_hex(4)
        token = safe_file_token(user)
        scope = "command" if commands else "full"
        fname = SUDOERS_JIT_PREFIX + token + (f"-cmd-{gid}" if commands else "")
        impl = detect_sudo_impl(self.ctx, policy)
        deny = policy.posix(policy.login["deny"])
        sudo_spec = role["sudo"] or {"commands": None, "runas": "ALL:ALL"}
        cmds = commands or sudo_spec["commands"]
        lines = [f"# el-jit grant {gid}: {user} role={role['name']} scope={scope}",
                 f"# approved-by={approver} expires={iso(expires)}",
                 f"# reason: {reason}" if reason else "# reason: (none)"]
        if cmds:
            option = f"NOTAFTER={sudoers_timestamp(expires)}" if impl == "sudo" else ""
            # NOPASSWD is never used for JIT: the user re-authenticates (MFA via PAM).
            lines.append(f"{user_list(user, deny)} ALL={cmnd_spec(cmds, sudo_spec['runas'], False, option)}")
        else:
            lines.append("# jit role has no sudo rules; grant is polkit-only")
        record = {"id": gid, "user": user, "role": role["name"], "scope": scope,
                  "commands": commands, "reason": reason, "ticket": ticket, "approver": approver,
                  "request_id": request_id, "granted_at": now, "expires_at": expires, "file": fname}
        warnings: list[str] = []
        with StateLock(self.ctx):
            state = self._load()
            if scope == "full":
                # one full grant per user: replace an existing one
                for old in [g for g in state["grants"] if g["user"] == user and g["scope"] == "full"]:
                    state["grants"].remove(old)
            atomic_write(self.ctx.path(fname), "\n".join(lines) + "\n", 0o440,
                         validate=visudo_validator(self.ctx, warnings))
            state["grants"].append(record)
            self._save(state)
            self._write_polkit(policy, state["grants"])
        self.emit("roles.granted", user=user, role=role["name"], grant_id=gid, scope=scope,
                  commands=commands, reason=reason, approver=approver, ticket=ticket,
                  expires_at=iso(expires), duration=format_duration(seconds))
        return {"status": "granted", "grant": record, "warnings": warnings}

    def _remove(self, policy, state, grants, event: str, reason: str, by: str | None = None):
        for g in grants:
            remove_file(self.ctx.path(g["file"]))
            state["grants"].remove(g)
        self._save(state)
        self._write_polkit(policy, state["grants"])
        for g in grants:
            fields = {"user": g["user"], "role": g["role"], "grant_id": g["id"], "scope": g["scope"],
                      "reason": reason}
            if by:
                fields["by"] = by
            self.emit(event, **fields)

    def revoke(self, user: str, reason: str = "manual", by: str = "root") -> dict:
        check_user(user)
        policy = self.policy(require_valid=False) if self.cache_state() in ("valid", "expired") else None
        with StateLock(self.ctx):
            state = self._load()
            hits = [g for g in state["grants"] if g["user"] == user]
            self._remove(policy, state, hits, "roles.revoked", reason, by)
        return {"revoked": [g["id"] for g in hits]}

    def expire(self, user: str | None = None, logout: bool = False) -> dict:
        now = int(self.ctx.now())
        cstate = self.cache_state()
        policy = None
        if cstate in ("valid", "expired"):
            policy = self.policy(require_valid=False)
        with StateLock(self.ctx):
            state = self._load()
            if cstate != "valid":
                hits, reason = list(state["grants"]), f"role cache {cstate}"
            elif logout:
                if not user:
                    raise ElPermError("--logout requires --user")
                if not policy.jit["revokeOnLogout"]:
                    return {"expired": []}
                hits, reason = [g for g in state["grants"] if g["user"] == user], "logout"
            else:
                hits = [g for g in state["grants"] if g["expires_at"] <= now
                        and (user is None or g["user"] == user)]
                reason = "time"
            # drop stale pending requests older than 24h
            state["requests"] = [r for r in state["requests"]
                                 if r["status"] == "pending" and now - r["requested_at"] < 86400]
            self._remove(policy, state, hits, "roles.expired", reason)
        return {"expired": [g["id"] for g in hits], "reason": reason if hits else None}

    def list(self) -> dict:
        state = self._load()
        now = int(self.ctx.now())
        for g in state["grants"]:
            g["remaining_seconds"] = max(0, g["expires_at"] - now)
        return {"grants": state["grants"],
                "requests": [r for r in state["requests"] if r["status"] == "pending"],
                "cache": self.cache_state()}

    # ---------------------------------------------------------------- polkit
    def _write_polkit(self, policy: Policy | None, grants: list[dict]):
        path = self.ctx.path(POLKIT_JIT)
        full = {g["user"]: g["expires_at"] * 1000 for g in grants if g["scope"] == "full"}
        if not full or policy is None:
            remove_file(path)
            return
        import json
        deny = policy.posix(policy.login["deny"])
        text = "\n".join([
            "// Generated by el-jit (enterprise-linux). DO NOT EDIT.",
            "// Active full JIT grants; each entry stops matching at its expiry (ms since epoch)",
            "// even if el-jit-expire.timer has not run yet.",
            "(function () {",
            f"    var GRANTS = {json.dumps(full, sort_keys=True)};",
            f"    var DENY_GROUPS = {json.dumps(deny)};",
            "    function inAny(subject, groups) {",
            "        for (var i = 0; i < groups.length; i++) {",
            "            if (subject.isInGroup(groups[i])) { return true; }",
            "        }",
            "        return false;",
            "    }",
            "    function active(subject) {",
            "        if (!Object.prototype.hasOwnProperty.call(GRANTS, subject.user)) { return false; }",
            "        return Date.now() < GRANTS[subject.user] && !inAny(subject, DENY_GROUPS);",
            "    }",
            "    polkit.addAdminRule(function (action, subject) {",
            "        return active(subject) ? [\"unix-user:\" + subject.user] : null;",
            "    });",
            "    polkit.addRule(function (action, subject) {",
            "        return active(subject) ? polkit.Result.AUTH_ADMIN_KEEP : polkit.Result.NOT_HANDLED;",
            "    });",
            "})();",
        ]) + "\n"
        atomic_write(path, text, 0o644)


def caller_identity(env=None) -> str:
    """Who is invoking el-jit: SUDO_USER / PKEXEC_UID owner, else the real user."""
    import pwd
    env = env if env is not None else os.environ
    if os.getuid() == 0:
        if env.get("SUDO_USER"):
            return env["SUDO_USER"]
        if env.get("PKEXEC_UID", "").isdigit():
            try:
                return pwd.getpwuid(int(env["PKEXEC_UID"])).pw_name
            except KeyError:
                pass
        return "root"
    return pwd.getpwuid(os.getuid()).pw_name
