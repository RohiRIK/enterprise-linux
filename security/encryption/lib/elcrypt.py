#!/usr/bin/env python3
"""elcrypt.py - shared helpers for the enterprise-linux encryption tools.

Python 3 standard library only. Called by the bash tools in ../sbin as
``python3 elcrypt.py <subcommand> ...`` and imported by el-encryption-facts.

Rules this module follows:
  * It never prints secret material (recovery keys, PINs, tokens).
    Functions that touch a secret read it from a file and only ever emit a
    fingerprint or a match/mismatch verdict.
  * Every state file is written atomically (temp file + fsync + rename) with
    restrictive permissions.
"""

import argparse
import base64
import datetime as _dt
import hashlib
import json
import os
import re
import secrets
import shutil
import sys
import tempfile

SCHEMA_VERSION = 1

# systemd "modhex" alphabet used for recovery keys (keyboard-layout safe).
MODHEX = "cbdefghijklnrtuv"
RECOVERY_KEY_RE = re.compile(r"[cbdefghijklnrtuv]{8}(?:-[cbdefghijklnrtuv]{8}){7}")
ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")

EXPECTED_CIPHER = "aes-xts-plain64"
EXPECTED_KEY_BITS = 512
EXPECTED_KDF = "argon2id"

# crypttab options owned by el-luks-enroll; everything else is preserved.
CRYPTTAB_MANAGED_OPTS = (
    "tpm2-device", "tpm2-pcrs", "tpm2-signature", "tpm2-pcrlock",
    "fido2-device", "fido2-cid", "fido2-rp",
)


# --------------------------------------------------------------------------
# small utilities
# --------------------------------------------------------------------------

def utcnow():
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0)


def isoformat(ts):
    return ts.isoformat().replace("+00:00", "Z")


def parse_iso(value):
    if not isinstance(value, str):
        raise ValueError("timestamp is not a string")
    v = value.strip()
    if v.endswith("Z"):
        v = v[:-1] + "+00:00"
    ts = _dt.datetime.fromisoformat(v)
    if ts.tzinfo is None:
        raise ValueError("timestamp has no timezone")
    return ts


def die(msg, code=1):
    sys.stderr.write("elcrypt: %s\n" % msg)
    sys.exit(code)


def atomic_write(path, data, mode=0o600, dir_mode=0o700):
    """Write *data* (str) to *path* atomically with the given permissions."""
    d = os.path.dirname(os.path.abspath(path))
    if not os.path.isdir(d):
        os.makedirs(d, mode=dir_mode, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".tmp-", dir=d)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    try:
        dfd = os.open(d, os.O_RDONLY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    except OSError:
        pass


def read_secret_file(path):
    with open(path, "rb") as fh:
        data = fh.read()
    # Callers store secrets without a trailing newline, but be tolerant.
    return data.rstrip(b"\r\n")


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def dig(obj, dotted):
    cur = obj
    for part in dotted.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        elif isinstance(cur, list) and part.isdigit() and int(part) < len(cur):
            cur = cur[int(part)]
        else:
            return None
    return cur


# --------------------------------------------------------------------------
# LUKS2 metadata
# --------------------------------------------------------------------------

def _int_list(values):
    out = []
    for v in values or []:
        try:
            out.append(int(v))
        except (TypeError, ValueError):
            continue
    return sorted(set(out))


def _clevis_pin(token):
    """Return the clevis pin name ("tang", "tpm2", "sss") of a clevis token."""
    jwe = token.get("jwe") or {}
    protected = jwe.get("protected") if isinstance(jwe, dict) else None
    if not protected:
        return None
    try:
        pad = "=" * (-len(protected) % 4)
        hdr = json.loads(base64.urlsafe_b64decode(protected + pad).decode("utf-8"))
        return (hdr.get("clevis") or {}).get("pin")
    except (ValueError, UnicodeDecodeError):
        return None


def summarize_luks(meta):
    """Turn ``cryptsetup luksDump --dump-json-metadata`` output into a
    stable summary. Never includes blobs, salts, digests or key material."""
    keyslots = {}
    for sid, ks in sorted((meta.get("keyslots") or {}).items(), key=lambda kv: int(kv[0])):
        kdf = ks.get("kdf") or {}
        area = ks.get("area") or {}
        keyslots[int(sid)] = {
            "id": int(sid),
            "type": ks.get("type"),
            "key_bits": int(ks.get("key_size", 0)) * 8,
            "kdf": kdf.get("type"),
            "area_cipher": area.get("encryption"),
            "token_ids": [],
            "method": "passphrase",
        }

    tokens = {}
    for tid, tok in sorted((meta.get("tokens") or {}).items(), key=lambda kv: int(kv[0])):
        ttype = tok.get("type", "")
        slots = _int_list(tok.get("keyslots"))
        entry = {"id": int(tid), "type": ttype, "keyslots": slots}
        method = None
        if ttype == "systemd-tpm2":
            pin = bool(tok.get("tpm2-pin", tok.get("tpm2_pin", False)))
            entry["pcrs"] = _int_list(tok.get("tpm2-pcrs", tok.get("tpm2_pcrs")))
            entry["signed_pcrs"] = _int_list(
                tok.get("tpm2_pubkey_pcrs", tok.get("tpm2-pubkey-pcrs")))
            entry["pcr_bank"] = tok.get("tpm2-pcr-bank", tok.get("tpm2_pcr_bank"))
            entry["pin"] = pin
            entry["pcrlock"] = bool(tok.get("tpm2_pcrlock", False))
            method = "tpm2+pin" if pin else "tpm2"
        elif ttype == "systemd-fido2":
            method = "fido2"
        elif ttype in ("systemd-recovery", "el-recovery"):
            # el-recovery: tag token added by el-recovery-escrow when it had
            # to fall back to `cryptsetup luksAddKey` (no systemd token).
            method = "recovery-key"
        elif ttype == "clevis":
            pin = _clevis_pin(tok)
            entry["clevis_pin"] = pin
            method = {"tang": "tang", "tpm2": "clevis-tpm2", "sss": "clevis-sss"}.get(pin, "clevis")
        else:
            method = ttype or "token"
        entry["method"] = method
        tokens[int(tid)] = entry
        for s in slots:
            if s in keyslots:
                keyslots[s]["token_ids"].append(int(tid))
                keyslots[s]["method"] = method

    segs = meta.get("segments") or {}
    seg0 = segs.get("0") or (next(iter(segs.values())) if segs else {})
    cipher = seg0.get("encryption")
    key_bits = None
    if keyslots:
        key_bits = next(iter(keyslots.values()))["key_bits"] or None

    warnings = []
    if cipher and cipher != EXPECTED_CIPHER:
        warnings.append("data cipher is %s, expected %s" % (cipher, EXPECTED_CIPHER))
    if key_bits and key_bits != EXPECTED_KEY_BITS:
        warnings.append("volume key is %d bits, expected %d" % (key_bits, EXPECTED_KEY_BITS))
    for ks in keyslots.values():
        # Token-backed slots (TPM2, FIDO2, recovery key) hold high-entropy
        # secrets; systemd deliberately uses a cheap PBKDF2 for them. Only
        # human passphrase slots need a memory-hard KDF.
        if not ks["token_ids"] and ks["kdf"] and ks["kdf"] != EXPECTED_KDF:
            warnings.append("keyslot %d (passphrase) uses kdf %s, expected %s"
                            % (ks["id"], ks["kdf"], EXPECTED_KDF))

    methods = sorted({ks["method"] for ks in keyslots.values()})
    tpm_pcrs = sorted({p for t in tokens.values() for p in t.get("pcrs", [])})
    signed = sorted({p for t in tokens.values() for p in t.get("signed_pcrs", [])})
    return {
        "cipher": cipher,
        "key_bits": key_bits,
        "cipher_spec": ("%s-%d" % (cipher, key_bits)) if cipher and key_bits else cipher,
        "keyslots": list(keyslots.values()),
        "tokens": list(tokens.values()),
        "unlock_methods": methods,
        "tpm_pcrs": tpm_pcrs,
        "tpm_signed_pcrs": signed,
        "warnings": warnings,
    }


def _load_json_arg(path):
    if path == "-":
        return json.load(sys.stdin)
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def cmd_luks_summary(a):
    print(json.dumps(summarize_luks(_load_json_arg(a.json)), indent=2, sort_keys=True))


def cmd_luks_query(a):
    """Small query language so bash never has to parse JSON itself."""
    s = summarize_luks(_load_json_arg(a.json))
    q = a.query
    out = []
    if q == "warnings":
        out = s["warnings"]
    elif q == "keyslots":
        out = [str(k["id"]) for k in s["keyslots"]]
    elif q.startswith("slots-by-method="):
        want = set(q.split("=", 1)[1].split(","))
        out = [str(k["id"]) for k in s["keyslots"] if k["method"] in want]
    elif q.startswith("tokens-by-method="):
        want = set(q.split("=", 1)[1].split(","))
        out = [str(t["id"]) for t in s["tokens"] if t["method"] in want]
    elif q.startswith("token-for-slot="):
        slot = int(q.split("=", 1)[1])
        out = [str(t["id"]) for t in s["tokens"] if slot in t["keyslots"]]
    elif q == "unlock-methods":
        out = s["unlock_methods"]
    elif q == "slot-count":
        out = [str(len(s["keyslots"]))]
    elif q.startswith("tpm2-slot-policy="):
        slot = int(q.split("=", 1)[1])
        for t in s["tokens"]:
            if t["type"] == "systemd-tpm2" and slot in t["keyslots"]:
                out = [json.dumps({"pcrs": t["pcrs"], "signed_pcrs": t["signed_pcrs"],
                                   "pin": t["pin"], "pcrlock": t["pcrlock"]}, sort_keys=True)]
    else:
        die("unknown query %r" % q, 2)
    for line in out:
        print(line)


def cmd_list_diff(a):
    """Print items present in NEW but not in OLD (space/newline separated)."""
    old = set(a.old.split())
    new = a.new.split()
    for item in new:
        if item not in old:
            print(item)


# --------------------------------------------------------------------------
# crypttab
# --------------------------------------------------------------------------

def _split_opts(opts):
    return [o for o in (opts or "").split(",") if o]


def _entry_matches(fields, uuid, device, name):
    if len(fields) < 2:
        return False
    target = fields[1]
    cands = set()
    if uuid:
        cands |= {"UUID=" + uuid, "/dev/disk/by-uuid/" + uuid, "uuid=" + uuid}
    if device:
        cands.add(device)
        try:
            cands.add(os.path.realpath(device))
        except OSError:
            pass
    if target in cands:
        return True
    return bool(name) and fields[0] == name


def compute_crypttab(text, uuid, device, name, mode, netdev=False, add_name=None):
    """Return (new_text, info). Pure function, no I/O."""
    lines = text.splitlines()
    out = []
    info = {"matched": False, "before": None, "after": None}
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            out.append(line)
            continue
        fields = stripped.split()
        if info["matched"] or not _entry_matches(fields, uuid, device, name):
            out.append(line)
            continue
        info["matched"] = True
        info["before"] = stripped
        while len(fields) < 4:
            fields.append("none" if len(fields) == 2 else "luks")
        opts = [o for o in _split_opts(fields[3])
                if o.split("=", 1)[0] not in CRYPTTAB_MANAGED_OPTS]
        opts = _apply_mode_opts(opts, mode, netdev)
        fields[3] = ",".join(opts) if opts else "luks"
        new = "\t".join(fields)
        info["after"] = new
        out.append(new)
    if not info["matched"] and add_name:
        opts = _apply_mode_opts(["luks"], mode, netdev)
        target = ("UUID=" + uuid) if uuid else device
        new = "\t".join([add_name, target, "none", ",".join(opts)])
        info["after"] = new
        info["added"] = True
        out.append(new)
    new_text = "\n".join(out) + ("\n" if out else "")
    info["changed"] = new_text != (text if text.endswith("\n") or not text else text + "\n")
    return new_text, info


def _apply_mode_opts(opts, mode, netdev):
    opts = list(opts)
    if mode in ("tpm2", "tpm2+pin"):
        opts.append("tpm2-device=auto")
    elif mode == "fido2":
        opts.append("fido2-device=auto")
    if netdev and "_netdev" not in opts:
        opts.append("_netdev")
    return opts


def cmd_crypttab_update(a):
    try:
        with open(a.crypttab, encoding="utf-8") as fh:
            text = fh.read()
        exists = True
    except FileNotFoundError:
        text, exists = "", False
    new_text, info = compute_crypttab(text, a.uuid, a.device, a.name, a.mode,
                                      netdev=a.netdev, add_name=a.add_name)
    info["path"] = a.crypttab
    info["backup"] = None
    info["dry_run"] = bool(a.dry_run)
    if info["changed"] and not a.dry_run:
        mode = 0o600
        if exists:
            st = os.stat(a.crypttab)
            mode = st.st_mode & 0o7777
            backup = "%s.el-backup-%s" % (a.crypttab, utcnow().strftime("%Y%m%dT%H%M%SZ"))
            shutil.copy2(a.crypttab, backup)
            os.chmod(backup, 0o600)
            info["backup"] = backup
        atomic_write(a.crypttab, new_text, mode=mode, dir_mode=0o755)
    print(json.dumps(info, sort_keys=True))


# --------------------------------------------------------------------------
# recovery keys and escrow state
# --------------------------------------------------------------------------

def cmd_genkey(a):
    """Generate a systemd-compatible recovery key (32 random bytes rendered
    as 64 modhex characters in groups of 8) into a new 0600 file."""
    raw = secrets.token_bytes(32)
    chars = "".join(MODHEX[b >> 4] + MODHEX[b & 0x0F] for b in raw)
    key = "-".join(chars[i:i + 8] for i in range(0, 64, 8))
    fd = os.open(a.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(key)


def cmd_extract_key(a):
    """Read captured `systemd-cryptenroll --recovery-key` stdout from a file,
    find the key, and write it (only it, no newline) to a new 0600 file.
    Exit 3 if no key was found. Never echoes the key."""
    with open(a.input, encoding="utf-8", errors="replace") as fh:
        text = ANSI_RE.sub("", fh.read())
    m = RECOVERY_KEY_RE.search(text)
    if not m:
        sys.exit(3)
    fd = os.open(a.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(m.group(0))


def cmd_redact(_a):
    """Filter stdin -> stdout, removing recovery keys and QR-code lines."""
    for line in sys.stdin:
        line = ANSI_RE.sub("", line)
        if any(ord(ch) > 127 for ch in line):
            continue  # QR codes / emoji glyphs may encode the key
        sys.stdout.write(RECOVERY_KEY_RE.sub("<redacted>", line))


def cmd_fingerprint(a):
    print(sha256_hex(read_secret_file(a.file)))


def cmd_escrow_body(a):
    """Build the JSON request body for an escrow backend into a new 0600
    file. The key is read from --key-file; metadata from --meta k=v."""
    key = read_secret_file(a.key_file).decode("utf-8")
    meta = {}
    for kv in a.meta or []:
        k, _, v = kv.partition("=")
        meta[k] = v
    if a.format == "vault":
        body = {"data": dict(meta, recovery_key=key)}
    elif a.format == "azure":
        tags = {k: v[:256] for k, v in meta.items()}
        body = {"value": key, "contentType": "application/x-luks-recovery-key", "tags": tags}
    elif a.format == "webhook":
        body = {"type": "luks-recovery-key", "recovery_key": key, "metadata": meta}
    elif a.format == "file":
        body = dict(meta, recovery_key=key)
    else:
        die("unknown body format", 2)
    fd = os.open(a.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump(body, fh, sort_keys=True)


def cmd_json_get(a):
    """Print one non-secret field from a JSON file (empty if missing)."""
    try:
        with open(a.json, encoding="utf-8") as fh:
            obj = json.load(fh)
    except (OSError, ValueError):
        sys.exit(3)
    v = dig(obj, a.path)
    if v is None:
        sys.exit(4)
    print(v if not isinstance(v, (dict, list)) else json.dumps(v, sort_keys=True))


def cmd_verify_field(a):
    """Compare sha256(field) of a JSON document with an expected fingerprint.
    Prints only 'match' or 'mismatch'. Exit 0 on match, 1 otherwise."""
    try:
        with open(a.json, encoding="utf-8") as fh:
            obj = json.load(fh)
    except (OSError, ValueError):
        print("mismatch")
        sys.exit(1)
    v = dig(obj, a.path)
    ok = isinstance(v, str) and secrets.compare_digest(
        sha256_hex(v.encode("utf-8")), a.fingerprint)
    print("match" if ok else "mismatch")
    sys.exit(0 if ok else 1)


def load_state(path):
    try:
        with open(path, encoding="utf-8") as fh:
            st = json.load(fh)
    except FileNotFoundError:
        st = {}
    st.setdefault("schema", SCHEMA_VERSION)
    st.setdefault("volumes", {})
    return st


def save_state(path, st):
    atomic_write(path, json.dumps(st, indent=2, sort_keys=True) + "\n")


def cmd_escrow_record(a):
    st = load_state(a.state)
    now = isoformat(utcnow())
    prev = st["volumes"].get(a.uuid)
    history = []
    if prev:
        history = prev.get("history", [])
        old = {k: prev.get(k) for k in ("keyslot", "backend", "target", "escrowed_at",
                                         "fingerprint_sha256")}
        old["superseded_at"] = now
        history.append(old)
    st["volumes"][a.uuid] = {
        "device": a.device,
        "keyslot": int(a.keyslot),
        "token_id": int(a.token_id) if a.token_id not in (None, "") else None,
        "backend": a.backend,
        "target": a.target,
        "escrowed_at": now,
        "fingerprint_sha256": a.fingerprint,
        "used": False,
        "used_at": None,
        "history": history[-10:],
    }
    save_state(a.state, st)
    print(json.dumps(st["volumes"][a.uuid], sort_keys=True))


def cmd_escrow_get(a):
    st = load_state(a.state)
    v = st["volumes"].get(a.uuid)
    if not v:
        sys.exit(4)
    if a.field:
        x = v.get(a.field)
        if x is None:
            sys.exit(4)
        print(x)
    else:
        print(json.dumps(v, sort_keys=True))


def cmd_escrow_mark_used(a):
    st = load_state(a.state)
    v = st["volumes"].get(a.uuid)
    if not v:
        die("no escrow record for %s" % a.uuid, 4)
    v["used"] = True
    v["used_at"] = isoformat(utcnow())
    save_state(a.state, st)


def cmd_escrow_due(a):
    """Exit 0 (and print reason) if rotation is due for this volume."""
    st = load_state(a.state)
    v = st["volumes"].get(a.uuid)
    if not v:
        print("not-escrowed")
        return
    if v.get("used"):
        print("used")
        return
    if a.max_age_days and a.max_age_days > 0:
        try:
            age = utcnow() - parse_iso(v.get("escrowed_at"))
            if age.days >= a.max_age_days:
                print("max-age")
                return
        except ValueError:
            print("bad-timestamp")
            return
    sys.exit(1)


def cmd_escrow_forget(a):
    st = load_state(a.state)
    if st["volumes"].pop(a.uuid, None) is not None:
        save_state(a.state, st)


def cmd_escrow_status(a):
    st = load_state(a.state)
    print(json.dumps(st, indent=2, sort_keys=True))


# --------------------------------------------------------------------------
# crypto-erase confirmation token claims
# --------------------------------------------------------------------------

def check_erase_claims(token, machine_id, uuids, now=None, max_age=3600, skew=300,
                       used_nonces=()):
    """Return a list of error strings (empty list = token acceptable)."""
    now = now or utcnow()
    errs = []
    if token.get("action") != "device.crypto-erase":
        errs.append("action is not device.crypto-erase")
    if token.get("machine_id") != machine_id:
        errs.append("machine_id does not match this device")
    allowed = token.get("luks_uuids")
    if not isinstance(allowed, list) or not allowed:
        errs.append("luks_uuids missing")
    elif "*" not in allowed:
        missing = [u for u in uuids if u not in allowed]
        if missing:
            errs.append("token does not cover volume(s): %s" % ",".join(missing))
    nonce = token.get("nonce")
    if not isinstance(nonce, str) or len(nonce) < 16:
        errs.append("nonce missing or shorter than 16 chars")
    elif nonce in used_nonces:
        errs.append("nonce already used (replay)")
    try:
        iat = parse_iso(token.get("issued_at"))
        exp = parse_iso(token.get("expires_at"))
        if iat - _dt.timedelta(seconds=skew) > now:
            errs.append("issued_at is in the future")
        if exp < now:
            errs.append("token expired")
        if (exp - iat).total_seconds() > max_age:
            errs.append("token lifetime exceeds %d seconds" % max_age)
    except (ValueError, TypeError) as e:
        errs.append("bad timestamps: %s" % e)
    return errs


def _read_nonces(path):
    try:
        with open(path, encoding="utf-8") as fh:
            return {ln.strip() for ln in fh if ln.strip()}
    except FileNotFoundError:
        return set()


def cmd_erase_check(a):
    with open(a.token, encoding="utf-8") as fh:
        token = json.load(fh)
    errs = check_erase_claims(token, a.machine_id, [u for u in a.uuids.split(",") if u],
                              max_age=a.max_age, used_nonces=_read_nonces(a.nonce_db))
    if errs:
        for e in errs:
            sys.stderr.write("token rejected: %s\n" % e)
        sys.exit(1)
    print(token.get("nonce"))


def cmd_erase_record_nonce(a):
    seen = _read_nonces(a.nonce_db)
    seen.add(a.nonce)
    atomic_write(a.nonce_db, "".join(n + "\n" for n in sorted(seen)))


# --------------------------------------------------------------------------
# generic small JSON state store (used by el-tpm-reseal)
# --------------------------------------------------------------------------

def _load_kv(path):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except FileNotFoundError:
        return {}


def cmd_kv_set(a):
    st = _load_kv(a.file)
    val = json.loads(a.value)
    if isinstance(val, dict):
        val.setdefault("updated_at", isoformat(utcnow()))
    st[a.key] = val
    atomic_write(a.file, json.dumps(st, indent=2, sort_keys=True) + "\n")


def cmd_kv_get(a):
    st = _load_kv(a.file)
    if a.key not in st:
        sys.exit(4)
    v = st[a.key]
    if a.field:
        v = dig(v, a.field)
        if v is None:
            sys.exit(4)
    if isinstance(v, list):
        for x in v:
            print(x)
    elif isinstance(v, dict):
        print(json.dumps(v, sort_keys=True))
    else:
        print(json.dumps(v) if isinstance(v, bool) else v)


def cmd_kv_del(a):
    st = _load_kv(a.file)
    if st.pop(a.key, None) is not None:
        atomic_write(a.file, json.dumps(st, indent=2, sort_keys=True) + "\n")


def cmd_kv_keys(a):
    for k in sorted(_load_kv(a.file)):
        print(k)


def cmd_kv_dump(a):
    print(json.dumps(_load_kv(a.file), indent=2, sort_keys=True))


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def main(argv=None):
    p = argparse.ArgumentParser(prog="elcrypt")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("luks-summary"); s.add_argument("json"); s.set_defaults(fn=cmd_luks_summary)
    s = sub.add_parser("luks-query"); s.add_argument("json"); s.add_argument("query")
    s.set_defaults(fn=cmd_luks_query)
    s = sub.add_parser("list-diff"); s.add_argument("old"); s.add_argument("new")
    s.set_defaults(fn=cmd_list_diff)

    s = sub.add_parser("crypttab-update")
    s.add_argument("--crypttab", required=True)
    s.add_argument("--uuid", default="")
    s.add_argument("--device", default="")
    s.add_argument("--name", default="")
    s.add_argument("--mode", required=True,
                   choices=["tpm2", "tpm2+pin", "tang", "fido2", "passphrase"])
    s.add_argument("--netdev", action="store_true")
    s.add_argument("--add-name", default="")
    s.add_argument("--dry-run", action="store_true")
    s.set_defaults(fn=cmd_crypttab_update)

    s = sub.add_parser("genkey"); s.add_argument("out"); s.set_defaults(fn=cmd_genkey)
    s = sub.add_parser("extract-key"); s.add_argument("input"); s.add_argument("out")
    s.set_defaults(fn=cmd_extract_key)
    s = sub.add_parser("redact"); s.set_defaults(fn=cmd_redact)
    s = sub.add_parser("fingerprint"); s.add_argument("file"); s.set_defaults(fn=cmd_fingerprint)
    s = sub.add_parser("escrow-body")
    s.add_argument("--format", required=True); s.add_argument("--key-file", required=True)
    s.add_argument("--out", required=True); s.add_argument("--meta", action="append")
    s.set_defaults(fn=cmd_escrow_body)
    s = sub.add_parser("json-get"); s.add_argument("json"); s.add_argument("path")
    s.set_defaults(fn=cmd_json_get)
    s = sub.add_parser("verify-field"); s.add_argument("json"); s.add_argument("path")
    s.add_argument("fingerprint"); s.set_defaults(fn=cmd_verify_field)

    s = sub.add_parser("escrow-record")
    for k in ("state", "uuid", "device", "keyslot", "backend", "target", "fingerprint"):
        s.add_argument("--" + k, required=True)
    s.add_argument("--token-id", default="")
    s.set_defaults(fn=cmd_escrow_record)
    s = sub.add_parser("escrow-get"); s.add_argument("--state", required=True)
    s.add_argument("--uuid", required=True); s.add_argument("--field", default="")
    s.set_defaults(fn=cmd_escrow_get)
    s = sub.add_parser("escrow-mark-used"); s.add_argument("--state", required=True)
    s.add_argument("--uuid", required=True); s.set_defaults(fn=cmd_escrow_mark_used)
    s = sub.add_parser("escrow-due"); s.add_argument("--state", required=True)
    s.add_argument("--uuid", required=True); s.add_argument("--max-age-days", type=int, default=0)
    s.set_defaults(fn=cmd_escrow_due)
    s = sub.add_parser("escrow-forget"); s.add_argument("--state", required=True)
    s.add_argument("--uuid", required=True); s.set_defaults(fn=cmd_escrow_forget)
    s = sub.add_parser("escrow-status"); s.add_argument("--state", required=True)
    s.set_defaults(fn=cmd_escrow_status)

    s = sub.add_parser("erase-check")
    s.add_argument("--token", required=True); s.add_argument("--machine-id", required=True)
    s.add_argument("--uuids", required=True); s.add_argument("--nonce-db", required=True)
    s.add_argument("--max-age", type=int, default=3600)
    s.set_defaults(fn=cmd_erase_check)
    s = sub.add_parser("erase-record-nonce"); s.add_argument("--nonce-db", required=True)
    s.add_argument("--nonce", required=True); s.set_defaults(fn=cmd_erase_record_nonce)

    s = sub.add_parser("kv-set"); s.add_argument("--file", required=True)
    s.add_argument("--key", required=True); s.add_argument("--value", required=True)
    s.set_defaults(fn=cmd_kv_set)
    s = sub.add_parser("kv-get"); s.add_argument("--file", required=True)
    s.add_argument("--key", required=True); s.add_argument("--field", default="")
    s.set_defaults(fn=cmd_kv_get)
    s = sub.add_parser("kv-del"); s.add_argument("--file", required=True)
    s.add_argument("--key", required=True); s.set_defaults(fn=cmd_kv_del)
    s = sub.add_parser("kv-keys"); s.add_argument("--file", required=True)
    s.set_defaults(fn=cmd_kv_keys)
    s = sub.add_parser("kv-dump"); s.add_argument("--file", required=True)
    s.set_defaults(fn=cmd_kv_dump)

    a = p.parse_args(argv)
    a.fn(a)


if __name__ == "__main__":
    main()
