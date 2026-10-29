#!/usr/bin/env python3
"""Tests for security/hardening. Run without root, no network:

    python3 -m unittest discover -s security/hardening/tests -v
or  security/hardening/tests/run-tests.sh

Everything writes into temporary directories; apply always runs with --root
pointing at a fake tree, and verify runs against stubbed commands.
"""
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = os.path.normpath(os.path.join(HERE, ".."))
BIN = os.path.join(BASE, "bin")
ROOTFS = os.path.join(BASE, "rootfs")
DATA = os.path.join(BASE, "data")
APPLY = os.path.join(BIN, "el-harden-apply")
VERIFY = os.path.join(BIN, "el-harden-verify")
USBGEN = os.path.join(BIN, "el-usbguard-rules")

LAYERS = {"mac", "allowlist", "device", "network", "kernel", "sandbox", "memsafe", "audit",
          "session"}
WHEN = {"any", "debian", "rhel", "apparmor", "selinux", "fapolicyd", "nftables", "firewalld",
        "ufw"}

UBUNTU = 'NAME="Ubuntu"\nID=ubuntu\nID_LIKE=debian\nVERSION_ID="24.04"\n'
UBUNTU26 = 'NAME="Ubuntu"\nID=ubuntu\nID_LIKE=debian\nVERSION_ID="26.04"\n'
RHEL = 'NAME="Red Hat Enterprise Linux"\nID="rhel"\nID_LIKE="fedora"\nVERSION_ID="9.4"\n'
ALMA10 = 'NAME="AlmaLinux"\nID="almalinux"\nID_LIKE="rhel centos fedora"\nVERSION_ID="10.0"\n'
ARCH = 'NAME="Arch Linux"\nID=arch\n'


def read(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def tsv(name):
    rows = []
    for line in read(os.path.join(DATA, name)).splitlines():
        if line.strip() and not line.startswith("#"):
            rows.append(line.split("\t"))
    return rows


def all_scripts():
    """(path, kind) for every executable script in the tree."""
    out = []
    for d, _, files in os.walk(BASE):
        if "__pycache__" in d:
            continue
        for f in files:
            p = os.path.join(d, f)
            try:
                with open(p, "rb") as fh:
                    first = fh.readline()
            except OSError:
                continue
            if first.startswith(b"#!") and b"bash" in first:
                out.append((p, "bash"))
            elif first.startswith(b"#!") and b"python3" in first:
                out.append((p, "python"))
    return out


def make_root(os_release, fstab="UUID=abcd / ext4 defaults 0 1\n", extra=None):
    root = tempfile.mkdtemp(prefix="el-hard-root-")
    os.makedirs(os.path.join(root, "etc"))
    with open(os.path.join(root, "etc/os-release"), "w") as fh:
        fh.write(os_release)
    if fstab is not None:
        with open(os.path.join(root, "etc/fstab"), "w") as fh:
            fh.write(fstab)
    for rel, content in (extra or {}).items():
        p = os.path.join(root, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as fh:
            fh.write(content)
    return root


def tracer_path():
    """A PATH containing only stubs that log any invocation (apply offline
    must never execute host tools)."""
    d = tempfile.mkdtemp(prefix="el-hard-trace-")
    log = os.path.join(d, "calls.log")
    for name in ("systemctl", "sysctl", "augenrules", "apparmor_parser", "fagenrules", "nft",
                 "firewall-cmd", "ufw", "udevadm", "dconf", "authselect", "apt-get", "dnf",
                 "getenforce", "nmcli"):
        p = os.path.join(d, name)
        with open(p, "w") as fh:
            fh.write("#!/bin/sh\necho \"%s $*\" >> '%s'\n" % (name, log))
        os.chmod(p, 0o755)
    return d, log


def run_apply(root, *extra, path=None):
    env = dict(os.environ)
    if path:
        env["PATH"] = path
    return subprocess.run([sys.executable, APPLY, "--root", root] + list(extra),
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          universal_newlines=True, env=env)


class StaticLint(unittest.TestCase):
    def test_bash_syntax(self):
        scripts = [p for p, k in all_scripts() if k == "bash"]
        self.assertTrue(scripts)
        for p in scripts:
            with self.subTest(script=p):
                r = subprocess.run(["bash", "-n", p], stderr=subprocess.PIPE,
                                   universal_newlines=True)
                self.assertEqual(r.returncode, 0, r.stderr)

    def test_python_syntax(self):
        scripts = [p for p, k in all_scripts() if k == "python"]
        self.assertGreaterEqual(len(scripts), 3)
        for p in scripts:
            with self.subTest(script=p):
                compile(read(p), p, "exec")

    @unittest.skipUnless(shutil.which("shellcheck"), "shellcheck not installed")
    def test_shellcheck(self):
        for p in [p for p, k in all_scripts() if k == "bash"]:
            with self.subTest(script=p):
                r = subprocess.run(["shellcheck", "-x", p], stdout=subprocess.PIPE,
                                   universal_newlines=True)
                self.assertEqual(r.returncode, 0, r.stdout)

    def test_scripts_executable(self):
        for p, _ in all_scripts():
            with self.subTest(script=p):
                self.assertTrue(os.stat(p).st_mode & stat.S_IXUSR, "%s not executable" % p)

    def test_sysctl_lines_parse(self):
        text = read(os.path.join(ROOTFS, "etc/sysctl.d/90-el-hardening.conf"))
        keys = []
        line_re = re.compile(r"^-?([a-z0-9_]+(\.[a-z0-9_]+)+) = (\S+)$")
        for n, line in enumerate(text.splitlines(), 1):
            if not line.strip() or line.startswith("#"):
                continue
            with self.subTest(line=n):
                m = line_re.match(line)
                self.assertIsNotNone(m, "unparseable sysctl line %d: %r" % (n, line))
                keys.append(m.group(1))
        self.assertEqual(len(keys), len(set(keys)), "duplicate sysctl keys")
        for required in ("kernel.kptr_restrict", "kernel.dmesg_restrict",
                         "kernel.unprivileged_bpf_disabled", "net.core.bpf_jit_harden",
                         "kernel.yama.ptrace_scope", "kernel.kexec_load_disabled",
                         "kernel.perf_event_paranoid", "fs.protected_hardlinks",
                         "fs.protected_symlinks", "fs.suid_dumpable",
                         "net.ipv4.conf.all.rp_filter", "net.ipv4.tcp_syncookies",
                         "net.ipv6.conf.all.accept_ra"):
            self.assertIn(required, keys)

    def test_sysctl_every_key_documented(self):
        lines = read(os.path.join(ROOTFS, "etc/sysctl.d/90-el-hardening.conf")).splitlines()
        for i, line in enumerate(lines):
            if line and not line.startswith("#"):
                # walk back over sibling keys to the nearest comment block
                j = i - 1
                while j >= 0 and lines[j] and not lines[j].startswith("#"):
                    j -= 1
                with self.subTest(key=line):
                    self.assertTrue(j >= 0 and lines[j].startswith("#"),
                                    "no comment above %r" % line)

    def test_modprobe_install_and_blacklist_pair(self):
        text = read(os.path.join(ROOTFS, "etc/modprobe.d/90-el-blacklist.conf"))
        inst = re.findall(r"^install (\S+) /bin/false$", text, re.M)
        black = re.findall(r"^blacklist (\S+)$", text, re.M)
        self.assertTrue(inst)
        self.assertEqual(sorted(inst), sorted(black))
        for mod in ("cramfs", "freevxfs", "hfs", "hfsplus", "jffs2", "dccp", "sctp", "rds",
                    "tipc", "firewire-core"):
            self.assertIn(mod, inst)
        for keep in ("squashfs", "usb-storage", "thunderbolt"):
            self.assertNotIn(keep, inst)
        for line in text.splitlines():
            if line and not line.startswith("#"):
                self.assertRegex(line, r"^(install \S+ /bin/false|blacklist \S+)$")

    def test_audit_rules_lint(self):
        d = os.path.join(ROOTFS, "etc/audit/rules.d")
        seen = set()
        names = sorted(os.listdir(d))
        self.assertEqual(names[0], "10-el-base.rules")
        self.assertEqual(names[-1], "99-el-finalize.rules")
        for name in names:
            for n, line in enumerate(read(os.path.join(d, name)).splitlines(), 1):
                if not line.strip() or line.startswith("#"):
                    continue
                with self.subTest(file=name, line=n):
                    self.assertTrue(line.startswith("-"), line)
                    if line.startswith(("-w ", "-a ")):
                        m = re.search(r"-k (\S+)$", line)
                        self.assertIsNotNone(m, "rule without key: " + line)
                        self.assertRegex(m.group(1), r"^el_[a-z_]+$")
                        self.assertNotIn(line, seen, "duplicate rule")
                        seen.add(line)
                        if line.startswith("-w "):
                            self.assertRegex(line, r"^-w /\S+ -p [rwxa]+ -k ")
                    else:
                        self.assertRegex(line, r"^(-D|-b \d+|--backlog_wait_time \d+|-f [012]|-i)$")
        finalize = read(os.path.join(d, "99-el-finalize.rules"))
        self.assertIn("#-e 2", finalize)
        self.assertNotRegex(finalize, r"^-e 2", "immutable mode must stay opt-in")

    def test_files_manifest_matches_rootfs(self):
        listed = {}
        for row in tsv("files.tsv"):
            self.assertEqual(len(row), 4, row)
            rel, layer, when, mode = row
            self.assertIn(layer, LAYERS, row)
            for part in when.split("+"):
                self.assertIn(part, WHEN, row)
            self.assertRegex(mode, r"^0[0-7]{3}$")
            self.assertNotIn(rel, listed, "listed twice: " + rel)
            listed[rel] = row
        on_disk = set()
        for d, _, files in os.walk(ROOTFS):
            for f in files:
                on_disk.add(os.path.relpath(os.path.join(d, f), ROOTFS))
        self.assertEqual(set(listed), on_disk)

    def test_services_manifest(self):
        for row in tsv("services.tsv"):
            with self.subTest(row=row):
                self.assertEqual(len(row), 6)
                unit, action, layer, when, profiles, reason = row
                self.assertRegex(unit, r"^[\w@.-]+\.(service|socket|mount|timer)$")
                self.assertIn(action, ("enable", "disable", "mask"))
                self.assertIn(layer, LAYERS)
                for part in when.split("+"):
                    self.assertIn(part, WHEN)
                self.assertIn(profiles, ("all", "workstation", "developer"))
                self.assertTrue(reason)

    def test_nftables_ruleset_shape(self):
        text = read(os.path.join(ROOTFS, "etc/nftables/el-baseline.nft"))
        self.assertEqual(text.count("{"), text.count("}"))
        self.assertIn("type filter hook input priority filter; policy drop;", text)
        self.assertIn("ct state { established, related } accept", text)
        self.assertIn('iif "lo" accept', text)
        self.assertIn("udp sport 67 udp dport 68 accept", text)
        self.assertIn("udp sport 547 udp dport 546", text)
        self.assertIn("packet-too-big", text)
        self.assertNotRegex(text, r"(?m)^\s*tcp dport (22|ssh)\b")
        self.assertNotIn("flush ruleset", text)

    @unittest.skipUnless(shutil.which("nft"), "nft not installed")
    def test_nftables_check(self):
        r = subprocess.run(["nft", "-c", "-f", os.path.join(ROOTFS, "etc/nftables/el-baseline.nft")],
                           stderr=subprocess.PIPE, universal_newlines=True)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_firewalld_zone_xml(self):
        import xml.etree.ElementTree as ET
        z = ET.parse(os.path.join(ROOTFS, "etc/firewalld/zones/el-workstation.xml")).getroot()
        self.assertEqual(z.tag, "zone")
        services = [s.get("name") for s in z.findall("service")]
        self.assertNotIn("ssh", services)
        self.assertNotIn("cockpit", services)
        self.assertIn("dhcpv6-client", services)

    def test_usbguard_conf(self):
        text = read(os.path.join(ROOTFS, "etc/usbguard/usbguard-daemon.conf"))
        self.assertIn("ImplicitPolicyTarget=block", text)
        self.assertIn("RuleFolder=/etc/usbguard/rules.d/", text)

    def test_selinux_module_skeleton(self):
        te = read(os.path.join(BASE, "selinux/eld.te"))
        fc = read(os.path.join(BASE, "selinux/eld.fc"))
        iff = read(os.path.join(BASE, "selinux/eld.if"))
        self.assertRegex(te, r"policy_module\(eld, \d+\.\d+\.\d+\)")
        self.assertIn("init_daemon_domain(eld_t, eld_exec_t)", te)
        self.assertEqual(te.count("`"), te.count("'"), "unbalanced m4 quotes in eld.te")
        self.assertEqual(iff.count("`"), iff.count("'"), "unbalanced m4 quotes in eld.if")
        for t in re.findall(r"object_r:(\w+)", fc):
            if t != "bin_t":
                self.assertIn("type %s;" % t, te)
        self.assertIn("interface(`eld_stream_connect'", iff)
        self.assertIn("/run/eld/api\\.sock", fc)

    def test_apparmor_profile_shape(self):
        text = read(os.path.join(ROOTFS, "etc/apparmor.d/usr.libexec.eld"))
        self.assertIn("profile eld /usr/libexec/eld {", text)
        self.assertEqual(text.count("{"), text.count("}"))
        self.assertIn("/run/eld/api.sock rw,", text)
        self.assertIn("deny @{HOMEDIRS}/** rwklx,", text)
        for target in re.findall(r"Px -> (\S+),", text):
            self.assertIn("profile %s {" % target, text)

    @unittest.skipUnless(shutil.which("apparmor_parser"), "apparmor_parser not installed")
    def test_apparmor_parse(self):
        r = subprocess.run(["apparmor_parser", "-Q", "-K",
                            os.path.join(ROOTFS, "etc/apparmor.d/usr.libexec.eld")],
                           stderr=subprocess.PIPE, universal_newlines=True)
        self.assertEqual(r.returncode, 0, r.stderr)


class UsbguardGenerator(unittest.TestCase):
    def gen(self, *args):
        root = tempfile.mkdtemp(prefix="el-usb-")
        self.addCleanup(shutil.rmtree, root)
        r = subprocess.run([sys.executable, USBGEN, "--root", root] + list(args),
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        return root, r

    def test_block(self):
        root, r = self.gen("--storage", "block")
        self.assertEqual(r.returncode, 0, r.stderr)
        rules = read(os.path.join(root, "etc/usbguard/rules.d/50-el-baseline.conf"))
        self.assertIn("block with-interface one-of { 08:*:* 06:*:* }", rules)
        self.assertIn("allow with-interface equals { 03:*:* }", rules)
        self.assertIn("allow with-interface equals { 09:*:* }", rules)
        self.assertNotIn("@", rules.replace("@STORAGE", ""), "unrendered placeholder")
        mode = stat.S_IMODE(os.stat(os.path.join(root, "etc/usbguard/rules.d/50-el-baseline.conf")).st_mode)
        self.assertEqual(mode, 0o600)
        self.assertFalse(os.path.exists(os.path.join(root, "etc/udev/rules.d/90-el-usb-storage-ro.rules")))

    def test_read_only_then_allow_removes_udev_rule(self):
        root, r = self.gen("--storage", "read-only")
        udev = os.path.join(root, "etc/udev/rules.d/90-el-usb-storage-ro.rules")
        self.assertTrue(os.path.exists(udev))
        self.assertIn("blockdev --setro", read(udev))
        r = subprocess.run([sys.executable, USBGEN, "--root", root, "--storage", "allow",
                            "--allow-id", "17EF:30B4"], stdout=subprocess.PIPE,
                           universal_newlines=True)
        self.assertEqual(r.returncode, 0)
        self.assertFalse(os.path.exists(udev))
        rules = read(os.path.join(root, "etc/usbguard/rules.d/50-el-baseline.conf"))
        self.assertIn("allow with-interface equals { 08:*:* }", rules)
        self.assertIn("allow id 17ef:30b4", rules)

    def test_invalid_id(self):
        _, r = self.gen("--allow-id", "not-an-id")
        self.assertEqual(r.returncode, 2)


class ApplyOffline(unittest.TestCase):
    def setUp(self):
        self.trace_dir, self.trace_log = tracer_path()
        self.addCleanup(shutil.rmtree, self.trace_dir)

    def apply(self, root, *extra):
        r = run_apply(root, *extra, path=self.trace_dir)
        return r

    def new_root(self, osr, **kw):
        root = make_root(osr, **kw)
        self.addCleanup(shutil.rmtree, root)
        return root

    def manifest(self, root):
        return json.loads(read(os.path.join(root, "var/lib/el/hardening/applied.json")))

    def exists(self, root, rel):
        return os.path.lexists(os.path.join(root, rel))

    def assertNoHostCommands(self):
        self.assertFalse(os.path.exists(self.trace_log),
                         "offline apply executed host commands: %s"
                         % (read(self.trace_log) if os.path.exists(self.trace_log) else ""))

    def test_ubuntu_workstation(self):
        root = self.new_root(UBUNTU)
        os.makedirs(os.path.join(root, "usr/bin"))
        suid = os.path.join(root, "usr/bin/fake-suid-helper")
        with open(suid, "w") as fh:
            fh.write("#!/bin/sh\n")
        os.chmod(suid, 0o4755)
        r = self.apply(root)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNoHostCommands()
        for rel in ("etc/sysctl.d/90-el-hardening.conf", "etc/modprobe.d/90-el-blacklist.conf",
                    "etc/audit/rules.d/80-el.rules", "etc/audit/rules.d/41-el-setuid.rules",
                    "etc/apparmor.d/usr.libexec.eld", "etc/nftables/el-baseline.nft",
                    "etc/nftables.conf", "etc/usbguard/usbguard-daemon.conf",
                    "etc/usbguard/rules.d/50-el-baseline.conf",
                    "etc/systemd/system/tmp.mount.d/50-el-options.conf",
                    "etc/dconf/db/local.d/locks/00-el-screensaver",
                    "etc/aide/aide.conf.d/90_el_paths",
                    "etc/systemd/system-preset/40-el-hardening.preset"):
            self.assertTrue(self.exists(root, rel), rel)
        for rel in ("etc/fapolicyd/rules.d/25-el-flatpak.rules",
                    "etc/firewalld/zones/el-workstation.xml"):
            self.assertFalse(self.exists(root, rel), rel)
        self.assertIn("-F path=/usr/bin/fake-suid-helper",
                      read(os.path.join(root, "etc/audit/rules.d/41-el-setuid.rules")))
        self.assertEqual(stat.S_IMODE(os.stat(os.path.join(
            root, "etc/usbguard/usbguard-daemon.conf")).st_mode), 0o600)
        for unit in ("ssh.service", "ssh.socket", "sshd.service"):
            self.assertEqual(os.readlink(os.path.join(root, "etc/systemd/system", unit)), "/dev/null")
        preset = read(os.path.join(root, "etc/systemd/system-preset/40-el-hardening.preset"))
        self.assertIn("enable nftables.service", preset)
        self.assertIn("enable apparmor.service", preset)
        self.assertIn("disable ufw.service", preset)
        self.assertIn("disable avahi-daemon.service", preset)
        self.assertNotIn("firewalld", preset)
        fstab = read(os.path.join(root, "etc/fstab"))
        self.assertIn("UUID=abcd / ext4", fstab)
        self.assertRegex(fstab, r"(?m)^/home /home\s+none\s+bind,nosuid,nodev,noexec")
        self.assertRegex(fstab, r"(?m)^tmpfs\s+/tmp\s+tmpfs\s+\S*noexec")
        ld = read(os.path.join(root, "etc/login.defs"))
        self.assertIn("ENCRYPT_METHOD\tYESCRYPT", ld)
        self.assertIn("system-db:local", read(os.path.join(root, "etc/dconf/profile/user")))
        m = self.manifest(root)
        self.assertEqual(m["distro"]["family"], "debian")
        self.assertEqual(m["mac"], "apparmor")
        self.assertEqual(m["firewall"], "nftables")
        self.assertEqual(m["mode"], "offline")
        self.assertTrue(m["home_noexec"])
        self.assertEqual(sorted(m["layers_applied"]), sorted(LAYERS))
        self.assertIn("not a certification", m["disclaimer"])

    def test_idempotent(self):
        root = self.new_root(UBUNTU26)
        self.assertEqual(self.apply(root).returncode, 0)
        before = read(os.path.join(root, "etc/fstab"))
        r = self.apply(root, "--json")
        self.assertEqual(r.returncode, 0, r.stderr)
        m = json.loads(r.stdout)
        changed = [f for f in m["files"] if f["action"] not in ("unchanged",)]
        self.assertEqual(changed, [], changed)
        self.assertFalse(any(e["changed"] for e in m["edits"]))
        self.assertFalse(m["changed"])
        self.assertEqual(before, read(os.path.join(root, "etc/fstab")))
        self.assertEqual(before.count("# BEGIN el-hardening"), 1)

    def test_backup_of_foreign_file(self):
        root = self.new_root(UBUNTU, extra={"etc/nftables.conf": "#!/usr/sbin/nft -f\nflush ruleset\n"})
        self.assertEqual(self.apply(root).returncode, 0)
        self.assertIn("flush ruleset", read(os.path.join(root, "etc/nftables.conf.el-orig")))
        self.assertIn("el-baseline.nft", read(os.path.join(root, "etc/nftables.conf")))

    def test_rhel_workstation(self):
        root = self.new_root(RHEL, extra={
            "etc/selinux/config": "SELINUX=permissive\nSELINUXTYPE=targeted\n",
            "etc/fapolicyd/fapolicyd.conf": "permissive = 1\nnice_val = 14\n",
            "etc/firewalld/firewalld.conf": "# comment\nDefaultZone=public\n",
            "etc/gdm/custom.conf": "[daemon]\nAutomaticLoginEnable=True\nAutomaticLogin=bob\n\n[security]\n",
            "etc/login.defs": "# shadow\nPASS_MAX_DAYS\t99999\nUMASK\t\t022\n",
            "etc/security/faillock.conf": "# deny = 3\n# silent\n",
        })
        r = self.apply(root)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNoHostCommands()
        for rel in ("etc/fapolicyd/rules.d/25-el-flatpak.rules",
                    "etc/fapolicyd/rules.d/35-el-writable-dirs.rules",
                    "etc/firewalld/zones/el-workstation.xml",
                    "etc/audit/rules.d/40-el-privilege.rules"):
            self.assertTrue(self.exists(root, rel), rel)
        for rel in ("etc/apparmor.d/usr.libexec.eld", "etc/nftables.conf",
                    "etc/nftables/el-baseline.nft", "etc/aide/aide.conf.d/90_el_paths"):
            self.assertFalse(self.exists(root, rel), rel)
        self.assertIn("SELINUX=enforcing", read(os.path.join(root, "etc/selinux/config")))
        fc = read(os.path.join(root, "etc/fapolicyd/fapolicyd.conf"))
        self.assertIn("permissive = 0", fc)
        self.assertIn("nice_val = 14", fc)
        self.assertIn("DefaultZone=el-workstation", read(os.path.join(root, "etc/firewalld/firewalld.conf")))
        gdm = read(os.path.join(root, "etc/gdm/custom.conf"))
        self.assertIn("AutomaticLoginEnable=false", gdm)
        self.assertNotIn("AutomaticLoginEnable=True", gdm)
        self.assertIn("[xdmcp]\nEnable=false", gdm)
        ld = read(os.path.join(root, "etc/login.defs"))
        self.assertIn("PASS_MAX_DAYS\t365", ld)
        self.assertNotIn("99999", ld)
        self.assertIn("ENCRYPT_METHOD\tSHA512", ld)
        self.assertEqual(ld.count("UMASK"), 1)
        fl = read(os.path.join(root, "etc/security/faillock.conf"))
        self.assertIn("deny = 5", fl)
        self.assertRegex(fl, r"(?m)^audit$")
        preset = read(os.path.join(root, "etc/systemd/system-preset/40-el-hardening.preset"))
        self.assertIn("enable firewalld.service", preset)
        self.assertIn("enable fapolicyd.service", preset)
        self.assertIn("disable cockpit.socket", preset)
        self.assertNotIn("nftables", preset)
        m = self.manifest(root)
        self.assertEqual((m["mac"], m["firewall"]), ("selinux", "firewalld"))
        self.assertFalse(m["fapolicyd_permissive"])

    def test_rhel10_developer_profile(self):
        root = self.new_root(ALMA10, extra={"etc/fapolicyd/fapolicyd.conf": "permissive = 0\n"})
        r = self.apply(root, "--profile", "developer")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn("untested release", r.stderr)
        self.assertIn("permissive = 1", read(os.path.join(root, "etc/fapolicyd/fapolicyd.conf")))
        fstab = read(os.path.join(root, "etc/fstab"))
        self.assertNotIn("/home", fstab)
        self.assertIn("/var/tmp", fstab)
        m = self.manifest(root)
        self.assertTrue(m["fapolicyd_permissive"])
        self.assertFalse(m["home_noexec"])

    def test_existing_tmp_entry_is_respected(self):
        root = self.new_root(UBUNTU, fstab="UUID=a / ext4 defaults 0 1\nUUID=b /tmp ext4 defaults 0 2\n")
        r = self.apply(root)
        self.assertEqual(r.returncode, 0)
        self.assertIn("/tmp already has its own /etc/fstab entry", r.stderr)
        fstab = read(os.path.join(root, "etc/fstab"))
        self.assertNotRegex(fstab, r"(?m)^tmpfs\s+/tmp\s")

    def test_dry_run_writes_nothing(self):
        root = self.new_root(RHEL)
        before = sorted(os.listdir(root))
        r = self.apply(root, "--dry-run")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("dry run", r.stdout)
        self.assertEqual(before, sorted(os.listdir(root)))
        self.assertEqual(read(os.path.join(root, "etc/fstab")), "UUID=abcd / ext4 defaults 0 1\n")
        self.assertEqual(sorted(os.listdir(os.path.join(root, "etc"))), ["fstab", "os-release"])

    def test_skip_layers(self):
        root = self.new_root(UBUNTU)
        r = self.apply(root, "--skip", "network,10", "--skip", "session")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertFalse(self.exists(root, "etc/nftables/el-baseline.nft"))
        self.assertFalse(self.exists(root, "etc/sysctl.d/90-el-hardening.conf"))
        self.assertFalse(self.exists(root, "etc/systemd/system/ssh.service"))
        self.assertFalse(self.exists(root, "etc/dconf/db/local.d/00-el-screensaver"))
        self.assertTrue(self.exists(root, "etc/audit/rules.d/10-el-base.rules"))
        m = self.manifest(root)
        self.assertEqual(m["layers_skipped"], ["kernel", "network", "session"])

    def test_bad_skip(self):
        root = self.new_root(UBUNTU)
        self.assertEqual(self.apply(root, "--skip", "nonsense").returncode, 2)

    def test_unknown_family_refused(self):
        root = self.new_root(ARCH)
        r = self.apply(root)
        self.assertEqual(r.returncode, 2)
        self.assertIn("--family", r.stderr)
        self.assertFalse(self.exists(root, "etc/sysctl.d/90-el-hardening.conf"))
        r = self.apply(root, "--family", "debian")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("untested release", r.stderr)

    def test_usb_policy_and_ufw(self):
        root = self.new_root(UBUNTU, extra={"etc/default/ufw": 'DEFAULT_INPUT_POLICY="ACCEPT"\n',
                                            "etc/ufw/ufw.conf": "ENABLED=no\n"})
        r = self.apply(root, "--usb-storage", "read-only", "--firewall", "ufw")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(self.exists(root, "etc/udev/rules.d/90-el-usb-storage-ro.rules"))
        self.assertIn('DEFAULT_INPUT_POLICY="DROP"', read(os.path.join(root, "etc/default/ufw")))
        self.assertIn("ENABLED=yes", read(os.path.join(root, "etc/ufw/ufw.conf")))
        self.assertFalse(self.exists(root, "etc/nftables.conf"))
        self.assertEqual(self.manifest(root)["usb_storage"], "read-only")

    def test_ufw_rejected_on_rhel(self):
        root = self.new_root(RHEL)
        self.assertEqual(self.apply(root, "--firewall", "ufw").returncode, 2)


# ---------------------------------------------------------------------------
# verify with stubbed commands
# ---------------------------------------------------------------------------

STUB = r'''#!{python}
import json, os, sys
name = os.path.basename(sys.argv[0])
with open(os.path.join(os.path.dirname(os.path.abspath(sys.argv[0])), "responses.json")) as fh:
    resp = json.load(fh)
key = " ".join([name] + sys.argv[1:])
entry = resp.get(key) or resp.get(name + " *")
if entry is None:
    sys.stderr.write("stub: no response for %r\n" % key)
    sys.exit(127)
sys.stdout.write(entry.get("out", "") + "\n")
sys.exit(entry.get("rc", 0))
'''


def sysctl_responses(override=None):
    text = read(os.path.join(ROOTFS, "etc/sysctl.d/90-el-hardening.conf"))
    resp = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        line = line.lstrip("-")
        k, _, v = line.partition("=")
        resp["sysctl -n %s" % k.strip()] = {"out": v.strip()}
    for k, v in (override or {}).items():
        resp["sysctl -n %s" % k] = v
    return resp


class VerifyStubbed(unittest.TestCase):
    def setUp(self):
        self.stubdir = tempfile.mkdtemp(prefix="el-hard-stub-")
        self.addCleanup(shutil.rmtree, self.stubdir)

    def stubs(self, responses):
        names = {k.split(" ")[0] for k in responses}
        for n in names:
            p = os.path.join(self.stubdir, n)
            with open(p, "w") as fh:
                fh.write(STUB.replace("{python}", sys.executable))
            os.chmod(p, 0o755)
        with open(os.path.join(self.stubdir, "responses.json"), "w") as fh:
            json.dump(responses, fh)

    def applied_root(self, osr, *apply_args, extra=None):
        root = make_root(osr, extra=extra)
        self.addCleanup(shutil.rmtree, root)
        trace, _ = tracer_path()
        self.addCleanup(shutil.rmtree, trace)
        r = run_apply(root, *apply_args, path=trace)
        self.assertEqual(r.returncode, 0, r.stderr)
        mounts = ("tmpfs /tmp tmpfs rw,nosuid,nodev,noexec,relatime 0 0\n"
                  "tmpfs /dev/shm tmpfs rw,nosuid,nodev,noexec 0 0\n"
                  "/dev/x /var/tmp ext4 rw,nosuid,nodev,noexec 0 0\n"
                  "/dev/x /home ext4 rw,nosuid,nodev,noexec 0 0\n")
        for rel, content in {"proc/self/mounts": mounts,
                             "proc/modules": "ext4 1 0 - Live 0x0\nnvme 1 0 - Live 0x0\n",
                             "sys/kernel/security/lockdown": "none [integrity] confidentiality\n",
                             "sys/module/module/parameters/sig_enforce": "Y\n"}.items():
            p = os.path.join(root, rel)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "w") as fh:
                fh.write(content)
        return root

    def verify(self, root, *extra):
        env = dict(os.environ, PATH=self.stubdir)
        r = subprocess.run([sys.executable, VERIFY, "--root", root] + list(extra),
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           universal_newlines=True, env=env)
        doc = json.loads(r.stdout)
        return r, doc

    def common_ok(self):
        audit_rules = "\n".join("-w /x%d -p wa -k el_test" % i for i in range(200))
        resp = sysctl_responses()
        resp.update({
            "mokutil --sb-state": {"out": "SecureBoot enabled"},
            "systemctl is-active auditd": {"out": "active"},
            "systemctl is-active usbguard": {"out": "active"},
            "systemctl is-active fapolicyd": {"out": "active"},
            "systemctl is-active ssh.service": {"out": "inactive", "rc": 3},
            "systemctl is-active ssh.socket": {"out": "inactive", "rc": 3},
            "systemctl is-active sshd.service": {"out": "inactive", "rc": 3},
            "systemctl is-active avahi-daemon.service": {"out": "inactive", "rc": 3},
            "auditctl -s": {"out": "enabled 1\nfailure 1\npid 123"},
            "auditctl -l": {"out": audit_rules},
            "ss -H -t -l -n": {"out": "LISTEN 0 4096 127.0.0.53%lo:53 0.0.0.0:*\n"
                                      "LISTEN 0 128 [::1]:631 [::]:*"},
            "sudo --version": {"out": "Sudo version 1.9.15p5"},
        })
        return resp

    def test_ubuntu_all_pass(self):
        root = self.applied_root(UBUNTU)
        resp = self.common_ok()
        resp.update({
            "aa-enabled": {"out": "Yes"},
            "nft list table inet el_filter": {"out": "table inet el_filter {\n chain input {\n"
                                                     "  type filter hook input priority filter; policy drop;"},
        })
        self.stubs(resp)
        r, doc = self.verify(root)
        fails = [c for c in doc["checks"] if c["status"] == "fail"]
        self.assertEqual(fails, [], json.dumps(fails, indent=1))
        self.assertEqual(r.returncode, 0)
        self.assertEqual(doc["schema"], "el.hardening.verify/v1")
        self.assertTrue(doc["compliant"])
        self.assertEqual(doc["host"]["family"], "debian")
        for c in doc["checks"]:
            self.assertEqual(set(c), {"id", "layer", "title", "status", "expected", "actual"})
            self.assertIn(c["status"], ("pass", "fail", "skip"))
        ids = {c["id"] for c in doc["checks"]}
        for want in ("boot.secure_boot", "kernel.sysctl.kernel.kptr_restrict",
                     "mac.apparmor_enabled", "allowlist.mount.tmp", "allowlist.mount.home",
                     "network.firewall_active", "network.sshd_service_off", "audit.rules_loaded",
                     "audit.journald_seal", "session.no_autologin", "device.usbguard_active"):
            self.assertIn(want, ids)
        self.assertEqual({c["status"] for c in doc["checks"] if c["id"] == "mac.eld_confined"},
                         {"skip"})

    def test_rhel_failures_detected(self):
        root = self.applied_root(RHEL, extra={"etc/fapolicyd/fapolicyd.conf": "permissive = 1\n",
                                              "etc/selinux/config": "SELINUX=permissive\n",
                                              "etc/firewalld/firewalld.conf": "DefaultZone=public\n"})
        resp = self.common_ok()
        resp.update(sysctl_responses({"kernel.kptr_restrict": {"out": "0"},
                                      "dev.tty.legacy_tiocsti": {"rc": 255, "out": ""}}))
        resp.update({
            "getenforce": {"out": "Permissive"},
            "firewall-cmd --state": {"out": "running"},
            "firewall-cmd --get-default-zone": {"out": "el-workstation"},
            "systemctl is-active sshd.service": {"out": "active"},
            "ss -H -t -l -n": {"out": "LISTEN 0 128 0.0.0.0:22 0.0.0.0:*"},
        })
        self.stubs(resp)
        r, doc = self.verify(root)
        self.assertEqual(r.returncode, 1)
        self.assertFalse(doc["compliant"])
        by_id = {c["id"]: c for c in doc["checks"]}
        self.assertEqual(by_id["kernel.sysctl.kernel.kptr_restrict"]["status"], "fail")
        self.assertEqual(by_id["kernel.sysctl.kernel.kptr_restrict"]["expected"], "2")
        self.assertEqual(by_id["kernel.sysctl.kernel.kptr_restrict"]["actual"], "0")
        self.assertEqual(by_id["kernel.sysctl.dev.tty.legacy_tiocsti"]["status"], "skip")
        self.assertEqual(by_id["mac.selinux_enforcing"]["status"], "fail")
        self.assertEqual(by_id["mac.selinux_config"]["status"], "pass")  # apply fixed config
        self.assertEqual(by_id["allowlist.fapolicyd_mode"]["status"], "pass")  # apply set 0
        self.assertEqual(by_id["network.sshd_service_off"]["status"], "fail")
        self.assertEqual(by_id["network.no_listeners"]["status"], "fail")
        self.assertEqual(by_id["network.firewall_zone"]["status"], "pass")

    def test_missing_tools_skip_not_fail(self):
        root = self.applied_root(UBUNTU26)
        self.stubs({"true *": {"out": ""}})  # PATH has no real tools at all
        r, doc = self.verify(root, "--layer", "boot", "--layer", "network", "--layer", "mac")
        self.assertEqual(r.returncode, 0, json.dumps(doc, indent=1))
        statuses = {c["id"]: c["status"] for c in doc["checks"]}
        self.assertEqual(statuses["boot.secure_boot"], "skip")
        self.assertEqual(statuses["boot.lockdown"], "pass")
        self.assertEqual(statuses["network.firewall_active"], "skip")


if __name__ == "__main__":
    unittest.main()
