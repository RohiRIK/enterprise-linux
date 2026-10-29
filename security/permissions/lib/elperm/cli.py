"""Command-line entry points: el-perm-render, el-jit, el-breakglass.

Each main(argv, ctx) takes an optional Context so tests can inject a temp
root, fake clock, stub runner and fake group resolver. There is deliberately
no environment-variable or flag to fake the clock in production use.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import __version__
from .breakglass import BreakGlass
from .cache import load_cache, store_bundle, write_device_cache, make_bundle
from .events import emitter_for
from .jit import Jit, caller_identity
from .policy import load_policy_file, validate_policy
from .render import MODE_DEGRADED, MODE_NORMAL, apply, check, check_nss
from .util import Context, ElPermError, format_duration, iso, parse_duration


def _out(args, obj, human: str | None = None):
    if getattr(args, "json", False):
        # one JSON document per line, so events and the result form JSON Lines
        print(json.dumps(obj, sort_keys=True, default=str))
    elif human is not None:
        print(human)


def _run(fn, argv, ctx):
    try:
        return fn(argv, ctx)
    except ElPermError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return exc.exit_code


def _ctx_from_args(args, ctx: Context | None) -> Context:
    if ctx is None:
        ctx = Context(root=Path(args.root))
    elif getattr(args, "root", None) and args.root != "/":
        ctx.root = Path(args.root)
    emitter_for(ctx, to_stdout=getattr(args, "json", False) and getattr(args, "events_stdout", True))
    return ctx


def _require_root(ctx: Context):
    if ctx.is_real_root and os.geteuid() != 0:
        raise ElPermError("must run as root (or use --root DIR for a test render)")


# =========================================================== el-perm-render
def _render(argv, ctx):
    p = argparse.ArgumentParser(prog="el-perm-render",
                                description="Validate the role policy and render sudoers/polkit/pam_access.")
    src = p.add_mutually_exclusive_group()
    src.add_argument("--policy", help="fresh policy from MDM sync (JSON); refreshes the signed cache")
    src.add_argument("--bundle", help="MDM-signed ed25519 bundle; verified and stored as the cache")
    p.add_argument("--pubkey", help="MDM public key for --bundle (default /etc/el/roles/mdm-signing.pub)")
    p.add_argument("--root", default="/", help="output root (default /); use a temp dir for testing")
    p.add_argument("--check", action="store_true", help="report drift, write nothing (exit 2 on drift)")
    p.add_argument("--validate-only", action="store_true", help="validate --policy and exit")
    p.add_argument("--check-nss", action="store_true", help="also report mapped groups NSS cannot resolve")
    p.add_argument("--sudo-impl", choices=["sudo", "sudo-rs"], help="override sudo implementation detection")
    p.add_argument("--strict-visudo", action="store_true", help="fail if visudo is unavailable")
    p.add_argument("--make-bundle", metavar="OUT", help="(MDM/test helper) sign --policy with --signing-key into OUT")
    p.add_argument("--signing-key", help="ed25519 private key for --make-bundle")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    p.add_argument("--version", action="version", version=__version__)
    args = p.parse_args(argv)
    args.events_stdout = False
    ctx = _ctx_from_args(args, ctx)
    if args.sudo_impl:
        ctx.sudo_impl = args.sudo_impl
    ctx.strict_visudo = ctx.strict_visudo or args.strict_visudo
    emit = ctx.emit

    if args.make_bundle:
        if not (args.policy and args.signing_key):
            raise ElPermError("--make-bundle needs --policy and --signing-key")
        raw = load_policy_file(args.policy)
        pol = validate_policy(raw)
        doc = make_bundle(ctx, raw, args.signing_key, pol.offline["graceDays"])
        Path(args.make_bundle).write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")
        _out(args, {"bundle": args.make_bundle, "expires_at": iso(doc["expires_at"])},
             f"wrote {args.make_bundle}")
        return 0

    if args.policy:
        raw = load_policy_file(args.policy)
        policy = validate_policy(raw)
        if args.validate_only:
            _out(args, {"valid": True, "policy": policy.name, "version": policy.version},
                 f"policy {policy.name} {policy.version}: valid")
            return 0
        mode = MODE_NORMAL
        if not args.check:
            _require_root(ctx)
            if policy.offline["signing"] == "ed25519":
                raise ElPermError("policy requires ed25519-signed bundles; use --bundle")
            write_device_cache(ctx, raw, policy.offline["graceDays"])
    else:
        if args.validate_only:
            raise ElPermError("--validate-only needs --policy")
        if args.bundle:
            if not args.check:
                _require_root(ctx)
            doc = json.loads(Path(args.bundle).read_text())
            if args.check:
                from .cache import check_doc
                status = check_doc(ctx, doc, args.pubkey)
            else:
                status = store_bundle(ctx, doc, args.pubkey)
        else:
            status = load_cache(ctx, args.pubkey)
        if status.state in ("missing", "invalid"):
            emit("roles.cache_invalid", reason=f"{status.state}: {status.reason}")
            if status.state == "missing":
                raise ElPermError(f"role cache missing: {status.reason}; nothing rendered")
            raise _cache_err(status)
        policy = validate_policy(status.policy)
        mode = MODE_NORMAL if status.state == "valid" else MODE_DEGRADED

    if args.check:
        report = check(ctx, policy, mode)
        if args.check_nss:
            report["nss_unresolved"] = check_nss(ctx, policy)
        if report["drift"]:
            emit("roles.drift", **{k: v for k, v in report.items() if isinstance(v, list) and v})
        human = "\n".join(
            [f"mode: {mode}", f"drift: {'YES' if report['drift'] else 'no'}"]
            + [f"  {k}: {', '.join(v)}" for k, v in report.items() if isinstance(v, list) and v])
        _out(args, report, human)
        return 2 if report["drift"] else 0

    _require_root(ctx)
    result = apply(ctx, policy, mode)
    if mode == MODE_DEGRADED:
        emit("roles.degraded", reason="offline grace period expired; elevated roles dropped",
             policy=policy.name, version=policy.version)
        # also revoke any JIT grants (elevation is unavailable offline-expired)
        Jit(ctx).expire()
    emit("roles.rendered", policy=policy.name, version=policy.version, mode=mode,
         files=result["written"])
    if args.check_nss:
        result["nss_unresolved"] = check_nss(ctx, policy)
    for w in result["warnings"]:
        print(f"warning: {w}", file=sys.stderr)
    _out(args, {k: v for k, v in result.items() if k != "manifest"},
         f"rendered {len(result['written'])} files (mode {mode}) under {ctx.root}")
    return 0


def _cache_err(status):
    from .util import CacheError
    return CacheError(f"role cache invalid: {status.reason}; nothing rendered (existing files kept)")


def render_main(argv=None, ctx: Context | None = None) -> int:
    return _run(_render, sys.argv[1:] if argv is None else argv, ctx)


def _common_parser():
    """--root/--json accepted before or after the subcommand."""
    c = argparse.ArgumentParser(add_help=False)
    c.add_argument("--root", default=argparse.SUPPRESS, help="output root (default /)")
    c.add_argument("--json", action="store_true", default=argparse.SUPPRESS,
                   help="print results and events as JSON Lines")
    return c


# =================================================================== el-jit
def _jit(argv, ctx):
    common = _common_parser()
    p = argparse.ArgumentParser(prog="el-jit", description="Just-in-time elevation.", parents=[common])
    sub = p.add_subparsers(dest="cmd", required=True)
    _orig_add = sub.add_parser
    sub.add_parser = lambda *a, **k: _orig_add(*a, parents=[common], **k)

    r = sub.add_parser("request", help="request elevation (runs as root via eld/pkexec/sudo broker)")
    r.add_argument("--reason", required=False)
    r.add_argument("--for", dest="duration")
    r.add_argument("--command", action="append", default=[], help="command-scoped; repeatable")
    r.add_argument("--ticket")
    r.add_argument("--user", help="requesting user (default: invoking user)")

    g = sub.add_parser("grant", help="grant elevation directly (helpdesk/admin)")
    g.add_argument("user")
    g.add_argument("--for", dest="duration", required=True)
    g.add_argument("--reason")
    g.add_argument("--command", action="append", default=[])
    g.add_argument("--ticket")

    a = sub.add_parser("approve", help="approve a pending request")
    a.add_argument("request_id")
    d = sub.add_parser("deny", help="deny a pending request")
    d.add_argument("request_id")

    v = sub.add_parser("revoke", help="revoke all grants of a user")
    v.add_argument("user")
    v.add_argument("--reason", default="manual")

    sub.add_parser("list", help="list active grants and pending requests")

    e = sub.add_parser("expire", help="remove expired grants (systemd timer / PAM hook)")
    e.add_argument("--user")
    e.add_argument("--logout", action="store_true", help="session closed: revoke this user's grants")

    args = p.parse_args(argv)
    args.root = getattr(args, "root", "/")
    args.json = getattr(args, "json", False)
    args.events_stdout = True
    ctx = _ctx_from_args(args, ctx)
    jit = Jit(ctx)
    caller = ctx.caller or caller_identity()
    if args.cmd != "list":
        _require_root(ctx)

    def secs(text):
        return parse_duration(text) if text else None

    if args.cmd == "request":
        user = args.user or caller
        if args.user and caller not in ("root", args.user):
            raise ElPermError("only root/eld may request on behalf of another user")
        res = jit.request(user, args.reason, secs(args.duration), args.command, args.ticket)
        human = (f"granted until {iso(res['grant']['expires_at'])} (id {res['grant']['id']})"
                 if res["status"] == "granted" else
                 f"pending approval: request id {res['request']['id']}")
    elif args.cmd == "grant":
        res = jit.grant(args.user, secs(args.duration), args.reason, args.command,
                        approver=caller, ticket=args.ticket)
        human = f"granted {args.user} until {iso(res['grant']['expires_at'])} (id {res['grant']['id']})"
    elif args.cmd == "approve":
        res = jit.approve(args.request_id, caller)
        human = f"approved: {res['grant']['user']} until {iso(res['grant']['expires_at'])}"
    elif args.cmd == "deny":
        res = jit.deny(args.request_id, caller)
        human = f"denied request {args.request_id}"
    elif args.cmd == "revoke":
        res = jit.revoke(args.user, args.reason, by=caller)
        human = f"revoked {len(res['revoked'])} grant(s) for {args.user}"
    elif args.cmd == "expire":
        res = jit.expire(args.user, args.logout)
        human = f"expired {len(res['expired'])} grant(s)"
    else:
        res = jit.list()
        lines = [f"cache: {res['cache']}"]
        for gr in res["grants"]:
            lines.append(f"grant {gr['id']} {gr['user']} {gr['scope']} expires {iso(gr['expires_at'])} "
                         f"({format_duration(gr['remaining_seconds']) if gr['remaining_seconds'] else 'expired'})")
        for rq in res["requests"]:
            lines.append(f"pending {rq['id']} {rq['user']} {format_duration(rq['seconds'])}: {rq['reason']}")
        human = "\n".join(lines)
    for w in res.get("warnings", []) if isinstance(res, dict) else []:
        print(f"warning: {w}", file=sys.stderr)
    _out(args, {"result": res}, human)
    return 0


def jit_main(argv=None, ctx: Context | None = None) -> int:
    return _run(_jit, sys.argv[1:] if argv is None else argv, ctx)


# ============================================================ el-breakglass
def _bg(argv, ctx):
    common = _common_parser()
    p = argparse.ArgumentParser(prog="el-breakglass", description="Break-glass account (LAPS-style).",
                                parents=[common])
    sub = p.add_subparsers(dest="cmd", required=True)
    _orig_add = sub.add_parser
    sub.add_parser = lambda *a, **k: _orig_add(*a, parents=[common], **k)
    r = sub.add_parser("rotate", help="generate, escrow and set a new password")
    r.add_argument("--if-due", action="store_true", help="only rotate when used or periodic rotation is due")
    r.add_argument("--reveal-to-stdout-for-escrow-pipe", action="store_true",
                   help="print the new password to stdout (refused when stdout is a terminal)")
    m = sub.add_parser("mark-used", help="record use: high-severity event + schedule rotation")
    m.add_argument("--note", default="")
    sub.add_parser("pam-hook", help="pam_exec entry point (reads PAM_* environment)")
    sub.add_parser("status", help="show rotation state (never the password)")
    args = p.parse_args(argv)
    args.root = getattr(args, "root", "/")
    args.json = getattr(args, "json", False)
    args.events_stdout = args.cmd != "rotate" or not args.reveal_to_stdout_for_escrow_pipe
    ctx = _ctx_from_args(args, ctx)
    bg = BreakGlass(ctx)
    if args.cmd == "status":
        res = bg.status()
        _out(args, res, "\n".join(f"{k}: {v}" for k, v in res.items()))
        return 0
    _require_root(ctx)
    if args.cmd == "rotate":
        stream = None
        if args.reveal_to_stdout_for_escrow_pipe:
            if sys.stdout.isatty():
                raise ElPermError("refusing to reveal the password to a terminal; pipe it to the escrow tool")
            stream = sys.stdout
        res = bg.rotate(if_due=args.if_due, reveal_stream=stream)
        if stream is None:
            _out(args, res, f"rotated: {res['rotated']} ({res.get('reason')})")
        else:
            print(f"rotated: {res['rotated']} ({res.get('reason')})", file=sys.stderr)
        return 0
    if args.cmd == "mark-used":
        res = bg.mark_used(source="manual", note=args.note)
        _out(args, res, f"break-glass use recorded; rotation due {res['rotate_due_at']}")
        return 0
    res = bg.pam_hook(dict(os.environ) if ctx.pam_env is None else ctx.pam_env)
    return 0  # never block a login from the hook


def breakglass_main(argv=None, ctx: Context | None = None) -> int:
    return _run(_bg, sys.argv[1:] if argv is None else argv, ctx)
