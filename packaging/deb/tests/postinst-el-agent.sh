#!/bin/sh
# Sandbox test for el-eld's postinst el-agent checks (review M3, L-12c).
# No root needed: runs a copy of postinst with /etc/passwd, /etc/login.defs
# and /run/systemd/system redirected into a temp dir, and getent, adduser,
# addgroup and systemctl stubbed on PATH. Also run by `cargo test`
# (crates/eld/tests/postinst.rs).
set -u
here=$(cd "$(dirname "$0")" && pwd)
postinst="$here/../el-eld/DEBIAN/postinst"
t=$(mktemp -d)
trap 'rm -rf "$t"' EXIT
mkdir -p "$t/bin" "$t/etc"
cat > "$t/bin/getent" <<'X'
#!/bin/sh
if [ "$1 $2" = "passwd el-agent" ] && [ -n "${DIR_AGENT:-}" ]; then
  echo "el-agent:*:5000:5000::/:/bin/sh"; exit 0
fi
[ "$1" = group ] && exit 0
exit 2
X
printf '#!/bin/sh\necho "$*" >> "%s/added"\n' "$t" > "$t/bin/adduser"
printf '#!/bin/sh\nexit 0\n' > "$t/bin/addgroup"
printf '#!/bin/sh\nexit 0\n' > "$t/bin/systemctl"
chmod +x "$t/bin/"*
sed -e "s#/etc/passwd#$t/etc/passwd#g" -e "s#/etc/login.defs#$t/etc/login.defs#g" \
    -e "s#/run/systemd/system#$t/no-systemd#g" "$postinst" > "$t/postinst"
echo "SYS_UID_MAX 999" > "$t/etc/login.defs"

fail=0
# case NAME EXPECTED_EXIT EXPECT_ADDUSER(yes/no) PASSWD_CONTENT [ENV]
check() {
  name=$1 want=$2 add=$3 passwd=$4 env=${5:-}
  printf '%s' "$passwd" > "$t/etc/passwd"
  rm -f "$t/added"
  out=$(env PATH="$t/bin:$PATH" $env sh "$t/postinst" configure 2>&1)
  got=$?
  added=no; [ -f "$t/added" ] && added=yes
  if [ "$got" != "$want" ] || [ "$added" != "$add" ] || printf '%s' "$out" | grep -q "Illegal number\|integer expression"; then
    echo "FAIL $name: exit $got (want $want), adduser $added (want $add): $out"
    fail=1
  else
    echo "ok   $name"
  fi
}

root='root:x:0:0::/root:/bin/sh
'
check "fresh install creates el-agent"   0 yes "$root"
check "comment line is not an account"   0 yes "$root#el-agent:x:990:990::/:/sbin/nologin
"
check "directory-only el-agent refused"  1 no  "$root" DIR_AGENT=1
check "local system el-agent accepted"   0 no  "${root}el-agent:x:990:990::/:/sbin/nologin
"
check "regular-uid el-agent refused"     1 no  "${root}el-agent:x:1500:1500::/:/bin/sh
"
check "uid 0 el-agent refused"           1 no  "${root}el-agent:x:0:0::/:/bin/sh
"
check "duplicate el-agent refused"       1 no  "${root}el-agent:x:990:990::/:/sbin/nologin
el-agent:x:991:991::/:/sbin/nologin
"
check "non-numeric uid refused"          1 no  "${root}el-agent:x:abc:990::/:/sbin/nologin
"
check "shared uid refused"               1 no  "${root}el-agent:x:990:990::/:/sbin/nologin
other:x:990:990::/:/sbin/nologin
"
echo "SYS_UID_MAX 499" > "$t/etc/login.defs"
check "uid above SYS_UID_MAX refused"    1 no  "${root}el-agent:x:600:600::/:/sbin/nologin
"
exit $fail
