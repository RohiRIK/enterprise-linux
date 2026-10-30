"""Unit tests for the image build helpers (no ISO or VM needed).

    python3 -m unittest discover -s image/tests -v
"""
import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest

import yaml

HERE = os.path.dirname(os.path.realpath(__file__))
IMAGE = os.path.dirname(HERE)


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


render = load("render_autoinstall", os.path.join(IMAGE, "render-autoinstall.py"))
report = load("check_boot_report", os.path.join(HERE, "check-boot-report.py"))

BASE = dict(INTERACTIVE="identity", TIMEZONE="Asia/Jerusalem", INSTALL_KEY="k3y",
            PROFILE="default", IDENTITY="", LATE_ARGS="", SHUTDOWN="reboot")
TEMPLATE = open(os.path.join(IMAGE, "autoinstall", "autoinstall.yaml.in")).read()


class Autoinstall(unittest.TestCase):
    def test_interactive_identity(self):
        doc = render.check(render.render(TEMPLATE, BASE))["autoinstall"]
        self.assertEqual(doc["interactive-sections"], ["identity"])
        self.assertEqual(doc["storage"]["layout"], {"name": "lvm", "password": "k3y"})
        self.assertFalse(doc["drivers"]["install"])
        self.assertEqual(doc["kernel"], {"package": "linux-generic"})
        self.assertIn("python3-yaml", doc["packages"])
        self.assertEqual(doc["shutdown"], "reboot")

    def test_test_identity(self):
        vals = dict(BASE, INTERACTIVE="", LATE_ARGS="--ci-report", SHUTDOWN="poweroff",
                    IDENTITY='  identity:\n    hostname: el-ci\n    realname: EL test\n'
                             '    username: eltest\n    password: "$6$x$y"')
        doc = render.check(render.render(TEMPLATE, vals))["autoinstall"]
        self.assertEqual(doc["interactive-sections"], [])
        self.assertEqual(doc["identity"]["username"], "eltest")
        self.assertIn("--ci-report", doc["late-commands"][0])

    def test_hardening_packages_listed(self):
        doc = yaml.safe_load(render.render(TEMPLATE, BASE))["autoinstall"]
        tsv = os.path.join(IMAGE, "..", "security", "hardening", "data", "packages.tsv")
        for line in open(tsv):
            cols = line.split("\t")
            if line.startswith("#") or len(cols) < 2 or cols[1] != "debian":
                continue
            self.assertIn(cols[0], doc["packages"])

    def test_missing_value(self):
        with self.assertRaises(SystemExit):
            render.render(TEMPLATE, {k: v for k, v in BASE.items() if k != "PROFILE"})

    def test_rejects_unencrypted(self):
        text = render.render(TEMPLATE, BASE).replace("name: lvm", "name: direct")
        with self.assertRaises(SystemExit):
            render.check(text)


GRUB = """set timeout=30
menuentry "Try or Install Ubuntu" {
\tset gfxpayload=keep
\tlinux\t/casper/vmlinuz  --- quiet splash
\tinitrd\t/casper/initrd
}
menuentry "Ubuntu (safe graphics)" {
\tlinux\t/casper/vmlinuz nomodeset --- quiet splash
\tinitrd\t/casper/initrd
}
"""


class PatchGrub(unittest.TestCase):
    def run_patch(self, cfg, extra):
        with tempfile.NamedTemporaryFile("w", suffix=".cfg", delete=False) as f:
            f.write(cfg)
        try:
            r = subprocess.run([sys.executable, os.path.join(IMAGE, "patch-grub.py"), f.name, extra],
                               capture_output=True, text=True)
            return r, open(f.name).read()
        finally:
            os.unlink(f.name)

    def test_args_before_separator(self):
        r, out = self.run_patch(GRUB, " autoinstall console=ttyS0,115200")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("/casper/vmlinuz  autoinstall console=ttyS0,115200 --- quiet", out)
        self.assertIn("nomodeset autoinstall console=ttyS0,115200 ---", out)
        self.assertIn('menuentry "Install Enterprise Linux"', out)
        self.assertIn('menuentry "Ubuntu (safe graphics)"', out)
        self.assertIn("set timeout=5", out)

    def test_no_extra_keeps_lines(self):
        r, out = self.run_patch(GRUB, "")
        self.assertEqual(r.returncode, 0)
        self.assertIn("/casper/vmlinuz  --- quiet splash", out)

    def test_no_casper(self):
        r, _ = self.run_patch("set timeout=1\n", "autoinstall")
        self.assertNotEqual(r.returncode, 0)


GOOD = """noise
EL-CI-REPORT-BEGIN
kernel: 7.0.0-14-generic
cmdline: BOOT_IMAGE=/vmlinuz root=/dev/mapper/ubuntu--vg-ubuntu--lv ro quiet splash lockdown=integrity module.sig_enforce=1
lockdown: none [integrity] confidentiality
sig_enforce: Y
secureboot: 1
eld: active
elctl-whoami:
user:   root (uid 0)
roles:  user, local-admin
install.json:
{"schema": "el.image.install/v1", "pending": []}
harden-verify:
{}
failed-units:
EL-CI-REPORT-END
"""


class BootReport(unittest.TestCase):
    def results(self, log):
        return dict(report.checks(report.parse(log)))

    def test_good(self):
        self.assertTrue(all(self.results(GOOD).values()), self.results(GOOD))

    def test_no_lockdown(self):
        res = self.results(GOOD.replace("none [integrity] confidentiality", "[none] integrity confidentiality"))
        self.assertFalse(res["lockdown active ([integrity] or stronger)"])

    def test_secure_boot_off(self):
        self.assertFalse(self.results(GOOD.replace("secureboot: 1", "secureboot: 0"))["Secure Boot enabled"])

    def test_missing_block(self):
        with self.assertRaises(SystemExit):
            report.parse("nothing here")


class BuildUki(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        os.makedirs(os.path.join(self.root, "boot"))
        os.makedirs(os.path.join(self.root, "etc", "kernel"))
        for name in ("vmlinuz-7.0.0-14-generic", "initrd.img-7.0.0-14-generic",
                     "vmlinuz-6.0.0-1-generic", "initrd.img-6.0.0-1-generic"):
            open(os.path.join(self.root, "boot", name), "w").close()
        open(os.path.join(self.root, "etc", "os-release"), "w").write("ID=ubuntu\n")
        self.cmdline("root=UUID=x ro lockdown=integrity module.sig_enforce=1")

    def cmdline(self, text):
        open(os.path.join(self.root, "etc", "kernel", "cmdline"), "w").write(text + "\n")

    def run_uki(self, *args):
        return subprocess.run([os.path.join(IMAGE, "uki", "el-build-uki"), "--root", self.root,
                               "--dry-run", *args], capture_output=True, text=True)

    def test_picks_newest_kernel_and_signs(self):
        r = self.run_uki("--sb-key", "/k", "--sb-cert", "/c", "--pcr-key", "/p", "--pcr-pub", "/q")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("vmlinuz-7.0.0-14-generic", r.stdout)
        self.assertIn("--secureboot-private-key=/k", r.stdout)
        self.assertIn("--pcr-private-key=/p", r.stdout)
        self.assertIn("el-7.0.0-14-generic.efi", r.stdout)

    def test_refuses_cmdline_without_lockdown(self):
        self.cmdline("root=UUID=x ro module.sig_enforce=1")
        self.assertNotEqual(self.run_uki().returncode, 0)

    def test_refuses_cmdline_without_sig_enforce(self):
        self.cmdline("root=UUID=x ro lockdown=integrity")
        self.assertNotEqual(self.run_uki().returncode, 0)

    def test_key_pairs(self):
        self.assertNotEqual(self.run_uki("--sb-key", "/k").returncode, 0)
        self.assertNotEqual(self.run_uki("--pcr-pub", "/q").returncode, 0)


if __name__ == "__main__":
    unittest.main()
