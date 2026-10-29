# shellcheck shell=bash
# el-common.sh - shared helpers for the enterprise-linux encryption tools.
#
# Sourced by the scripts in ../sbin. Bash + coreutils + python3 (stdlib) only.
#
# Environment overrides (intended for tests and image builds; every one of
# them already requires the caller to control the process environment, i.e.
# to be root on a real system):
#   EL_LIBDIR           directory holding this file, elcrypt.py and escrow.d/
#   EL_CONF             config file           (default /etc/el/encryption.conf)
#   EL_STATE_DIR        state directory       (default /var/lib/el/encryption)
#   EL_CRYPTTAB         crypttab path         (default /etc/crypttab)
#   EL_RUN_DIR          private scratch base  (default /run/el, else $TMPDIR)
#   EL_MACHINE_ID_FILE  machine id file       (default /etc/machine-id)
#   EL_SKIP_ROOT_CHECK  1 = do not insist on uid 0 (tests only)

: "${EL_CONF:=/etc/el/encryption.conf}"
: "${EL_STATE_DIR:=/var/lib/el/encryption}"
: "${EL_CRYPTTAB:=/etc/crypttab}"
: "${EL_MACHINE_ID_FILE:=/etc/machine-id}"
: "${EL_DRY_RUN:=0}"
: "${EL_QUIET:=0}"
EL_PROG="${EL_PROG:-$(basename "$0")}"
EL_PY="${EL_LIBDIR}/elcrypt.py"

el_log() {
    [ "$EL_QUIET" = 1 ] && return 0
    printf '%s: %s\n' "$EL_PROG" "$*" >&2
}

el_warn() { printf '%s: WARNING: %s\n' "$EL_PROG" "$*" >&2; }

el_die() {
    printf '%s: ERROR: %s\n' "$EL_PROG" "$1" >&2
    exit "${2:-1}"
}

# Send a line to the journal / syslog if logger exists. Never pass secrets.
el_audit() {
    if command -v logger >/dev/null 2>&1; then
        logger -t "el-encryption" -- "$EL_PROG: $*" 2>/dev/null || true
    fi
}

el_py() { python3 "$EL_PY" "$@"; }

# Print a command in copy-pasteable form.
el_fmt_cmd() {
    local out="" a
    for a in "$@"; do
        out+="$(printf '%q' "$a") "
    done
    printf '%s' "${out% }"
}

# Run a state-changing command, or only print it when EL_DRY_RUN=1.
# Secrets must be passed through exported environment variables (NEWPIN,
# PASSWORD, NEWPASSWORD) or files, never as arguments; their values are
# never printed.
el_run() {
    local envnote="" v
    for v in NEWPIN PASSWORD NEWPASSWORD; do
        if [ -n "${!v:-}" ]; then envnote+="$v=<redacted> "; fi
    done
    if [ "$EL_DRY_RUN" = 1 ]; then
        printf '[dry-run] %s%s\n' "$envnote" "$(el_fmt_cmd "$@")" >&2
        return 0
    fi
    [ "$EL_QUIET" = 1 ] || printf '+ %s%s\n' "$envnote" "$(el_fmt_cmd "$@")" >&2
    "$@"
}

el_require_root() {
    [ "${EL_SKIP_ROOT_CHECK:-0}" = 1 ] && return 0
    [ "$(id -u)" -eq 0 ] || el_die "must run as root" 77
}

el_require_cmd() {
    local c
    for c in "$@"; do
        command -v "$c" >/dev/null 2>&1 || el_die "required command not found: $c" 69
    done
}

# Load KEY=VALUE config without sourcing it (no code execution). Only keys
# matching ^EL_[A-Z0-9_]+$ are accepted; values already present in the
# environment win over the file. A value may be quoted ('...' or "...", taken
# literally); an unquoted value ends at the first whitespace-preceded '#'.
el_load_config() {
    local file="${1:-$EL_CONF}" line key val
    [ -r "$file" ] || return 0
    while IFS= read -r line || [ -n "$line" ]; do
        line="${line#"${line%%[![:space:]]*}"}"
        case "$line" in ''|'#'*) continue ;; esac
        key="${line%%=*}"
        val="${line#*=}"
        [ "$key" != "$line" ] || continue
        if ! [[ "$key" =~ ^EL_[A-Z0-9_]+$ ]]; then
            el_warn "ignoring invalid config key in $file: $key"
            continue
        fi
        case "$val" in
            \"*\"*) val="${val#\"}"; val="${val%%\"*}" ;;
            \'*\'*) val="${val#\'}"; val="${val%%\'*}" ;;
            *) val="${val%%[[:space:]]#*}"   # unquoted: drop inline " # comment"
               val="${val%"${val##*[![:space:]]}"}" ;;
        esac
        if [ -z "${!key+x}" ]; then
            printf -v "$key" '%s' "$val"
            export "${key?}"
        fi
    done <"$file"
}

# Private scratch directory (0700) for secret material; removed on exit.
# Prefers a tmpfs under /run so keys never touch persistent storage.
# Call directly (not in $(...)) so EL_SECRET_DIR is set in this shell.
EL_SECRET_DIR=""
el_secret_dir() {
    if [ -n "$EL_SECRET_DIR" ]; then return 0; fi
    local base="${EL_RUN_DIR:-/run/el}"
    if ! { mkdir -p "$base" 2>/dev/null && chmod 0700 "$base" 2>/dev/null; } || [ ! -w "$base" ]; then
        base="${TMPDIR:-/tmp}"
    fi
    EL_SECRET_DIR="$(umask 077; mktemp -d "$base/el-enc.XXXXXXXX")"
    chmod 0700 "$EL_SECRET_DIR"
}

el_shred() {
    local f
    for f in "$@"; do
        [ -f "$f" ] || continue
        if command -v shred >/dev/null 2>&1; then
            shred -u -z "$f" 2>/dev/null || rm -f "$f"
        else
            rm -f "$f"
        fi
    done
}

el_cleanup_secrets() {
    if [ -n "$EL_SECRET_DIR" ] && [ -d "$EL_SECRET_DIR" ]; then
        local f
        for f in "$EL_SECRET_DIR"/* "$EL_SECRET_DIR"/.[!.]*; do
            [ -e "$f" ] && el_shred "$f"
        done
        rm -rf "$EL_SECRET_DIR"
    fi
}

# systemd major version, from `systemd-cryptenroll --version` ("systemd 255 (...)").
el_systemd_version() {
    command -v systemd-cryptenroll >/dev/null 2>&1 || { echo 0; return 0; }
    local v
    v="$(systemd-cryptenroll --version 2>/dev/null | head -n1 | awk '{print $2}')"
    v="${v%%[!0-9]*}"
    echo "${v:-0}"
}

# --- LUKS helpers ---------------------------------------------------------

# Abort unless DEVICE is LUKS2. LUKS1 is refused explicitly.
el_assert_luks2() {
    local dev="$1"
    [ -e "$dev" ] || el_die "device not found: $dev" 66
    if cryptsetup isLuks --type luks2 "$dev" >/dev/null 2>&1; then
        return 0
    fi
    if cryptsetup isLuks "$dev" >/dev/null 2>&1; then
        el_die "$dev is LUKS1. TPM2/FIDO2 tokens need LUKS2. Convert offline first (back up the header: 'cryptsetup luksHeaderBackup', then 'cryptsetup convert --type luks2', then re-add passphrases so they get argon2id)." 65
    fi
    el_die "$dev is not a LUKS device" 65
}

# Dump LUKS2 JSON metadata of DEVICE into FILE.
el_luks_dump() {
    local dev="$1" out="$2"
    cryptsetup luksDump --dump-json-metadata "$dev" >"$out" 2>/dev/null \
        || el_die "cannot read LUKS2 metadata of $dev (needs cryptsetup >= 2.4 and read access)" 74
}

el_luks_uuid() { cryptsetup luksUUID "$1" 2>/dev/null; }

# Print every LUKS device path. Uses lsblk's FSTYPE (from udev); when udev
# has no data (containers, early boot) falls back to `cryptsetup isLuks`.
el_discover_luks() {
    local path fstype type
    lsblk -rnpo PATH,TYPE,FSTYPE 2>/dev/null | while read -r path type fstype; do
        if [ "${fstype:-}" = crypto_LUKS ]; then
            printf '%s\n' "$path"
        elif [ -z "${fstype:-}" ] && case "$type" in disk|part|loop|lvm|md*|raid*) true ;; *) false ;; esac \
             && cryptsetup isLuks "$path" >/dev/null 2>&1; then
            printf '%s\n' "$path"
        fi
    done
}

el_join() { local IFS="$1"; shift; printf '%s' "$*"; }

# Remove keyslots without needing an unlock credential.
el_wipe_slots() {
    local dev="$1"; shift
    [ "$#" -gt 0 ] || return 0
    if command -v systemd-cryptenroll >/dev/null 2>&1; then
        el_run systemd-cryptenroll "--wipe-slot=$(el_join , "$@")" "$dev"
    else
        local s
        for s in "$@"; do el_run cryptsetup luksKillSlot -q "$dev" "$s"; done
    fi
}

# --- HTTP helpers for escrow backends ----------------------------------------

# Write "Name: <prefix><token>" into a new 0600 header file for `curl -H @file`
# so the token never appears in a process argument list.
el_make_header() {
    local out="$1" name="$2" tokfile="$3" prefix="${4:-}" tok
    [ -r "$tokfile" ] || el_die "cannot read token file: $tokfile" 66
    tok="$(<"$tokfile")"
    tok="${tok%"${tok##*[![:space:]]}"}"
    [ -n "$tok" ] || el_die "token file is empty: $tokfile" 66
    (umask 077; printf '%s: %s%s\n' "$name" "$prefix" "$tok" >"$out")
}

# el_curl RESPONSE_FILE CURL_ARGS... -> prints the HTTP status code.
# Only https is allowed unless EL_ALLOW_INSECURE_HTTP=1 (lab use).
el_curl() {
    local resp="$1"; shift
    local proto="=https"
    [ "${EL_ALLOW_INSECURE_HTTP:-0}" = 1 ] && proto="=http,https"
    curl -sS --proto "$proto" --max-time "${EL_HTTP_TIMEOUT:-30}" --retry 2 \
        -o "$resp" -w '%{http_code}' "$@"
}

el_http_ok() { case "$1" in 2[0-9][0-9]) return 0 ;; *) return 1 ;; esac; }
