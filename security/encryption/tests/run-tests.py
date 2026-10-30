#!/usr/bin/env python3
"""Unit/functional tests for security/encryption.

Runs every tool against mock binaries (tests/mocks) so it needs no root, no
TPM, no cryptsetup and no network. A "device" is a JSON file the mocks treat
as a LUKS header. Usage:

    python3 security/encryption/tests/run-tests.py [-v] [TestClass.test_name]
"""
import base64
import datetime as dt
import glob
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import warnings

sys.dont_write_bytecode = True

warnings.simplefilter("ignore", ResourceWarning)

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SBIN = os.path.join(ROOT, "sbin")
LIB = os.path.join(ROOT, "lib")
MOCKS = os.path.join(HERE, "mocks")
BASH_SCRIPTS = sorted(
    [p for p in glob.glob(os.path.join(SBIN, "*")) if open(p).readline().endswith("bash\n")]
    + glob.glob(os.path.join(LIB, "escrow.d", "*"))
    + [os.path.join(LIB, "el-common.sh"), os.path.join(HERE, "integration-loop.sh")])

UUID = "0b9f6c1e-1111-4222-8333-944455556666"


def make_device(path, version=2, cipher="aes-xts-plain64", key_size=64, slots=None,
                tokens=None, uuid=UUID, tpm_ok=True):
    """slots: {id: kdf}; tokens: {id: token-dict}."""
    slots = slots if slots is not None else {0: "argon2id"}
    d = {
        "_mock": {"version": version, "uuid": uuid, "tpm_ok": tpm_ok},
        "keyslots": {str(k): {"type": "luks2", "key_size": key_size,
                              "area": {"type": "raw", "encryption": cipher, "key_size": key_size},
                              "kdf": {"type": kdf}} for k, kdf in slots.items()},
        "tokens": {str(k): v for k, v in (tokens or {}).items()},
        "segments": {"0": {"type": "crypt", "offset": "16777216", "size": "dynamic",
                           "encryption": cipher, "sector_size": 512}},
        "digests": {}, "config": {"json_size": "12288"},
    }
    with open(path, "w") as fh:
        json.dump(d, fh)
    return path


def tpm_token(slot, pcrs=(7,), signed=(), pin=False):
    t = {"type": "systemd-tpm2", "keyslots": [str(slot)], "tpm2-blob": "AAAA",
         "tpm2-pcrs": list(pcrs), "tpm2-pcr-bank": "sha256", "tpm2-pin": pin}
    if signed:
        t["tpm2_pubkey_pcrs"] = list(signed)
        t["tpm2_pubkey"] = "UFVC"
    return t


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="el-enc-test-")
        self.mockdir = os.path.join(self.tmp, "mock")
        os.makedirs(self.mockdir)
        self.log = os.path.join(self.tmp, "calls.log")
        self.state = os.path.join(self.tmp, "state")
        self.crypttab = os.path.join(self.tmp, "crypttab")
        self.conf = os.path.join(self.tmp, "encryption.conf")
        self.dev = os.path.join(self.tmp, "nvme0n1p3")
        with open(os.path.join(self.tmp, "machine-id"), "w") as fh:
            fh.write("4c4c4544004d3510804bc3c04f4e3132\n")
        with open(self.crypttab, "w") as fh:
            fh.write("# test crypttab\nluks-root UUID=%s none luks,discard\n" % UUID)
        open(self.conf, "w").close()
        self.env = dict(os.environ)
        self.env.update({
            "PATH": MOCKS + os.pathsep + os.environ.get("PATH", "/usr/bin:/bin"),
            "PYTHONDONTWRITEBYTECODE": "1",
            "EL_SKIP_ROOT_CHECK": "1",
            "EL_CONF": self.conf,
            "EL_STATE_DIR": self.state,
            "EL_CRYPTTAB": self.crypttab,
            "EL_RUN_DIR": os.path.join(self.tmp, "run"),
            "EL_MACHINE_ID_FILE": os.path.join(self.tmp, "machine-id"),
            "MOCK_DIR": self.mockdir,
            "MOCK_LOG": self.log,
        })
        for k in list(self.env):
            if k.startswith("EL_") and k not in (
                    "EL_SKIP_ROOT_CHECK", "EL_CONF", "EL_STATE_DIR", "EL_CRYPTTAB",
                    "EL_RUN_DIR", "EL_MACHINE_ID_FILE"):
                del self.env[k]

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_tool(self, name, *args, env=None, rc=0, stdin=None):
        e = dict(self.env, **(env or {}))
        p = subprocess.run([os.path.join(SBIN, name)] + list(args), env=e,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                           stdin=stdin if stdin is not None else subprocess.DEVNULL)
        if rc is not None and p.returncode != rc:
            self.fail("%s %s: rc=%d (want %d)\nSTDOUT:\n%s\nSTDERR:\n%s"
                      % (name, " ".join(args), p.returncode, rc, p.stdout, p.stderr))
        return p

    def calls(self, cmd=None):
        if not os.path.exists(self.log):
            return []
        with open(self.log) as fh:
            out = [json.loads(line) for line in fh]
        return [c for c in out if cmd is None or c["cmd"] == cmd]

    def devjson(self):
        with open(self.dev) as fh:
            return json.load(fh)

    def write_conf(self, **kv):
        with open(self.conf, "w") as fh:
            for k, v in kv.items():
                fh.write("%s=%s\n" % (k, v))

    def read_state(self):
        with open(os.path.join(self.state, "escrow.json")) as fh:
            return json.load(fh)


class StaticChecks(Base):
    def test_bash_syntax(self):
        for s in BASH_SCRIPTS:
            p = subprocess.run(["bash", "-n", s], stderr=subprocess.PIPE, text=True)
            self.assertEqual(p.returncode, 0, "%s: %s" % (s, p.stderr))

    def test_python_compiles(self):
        for s in [os.path.join(LIB, "elcrypt.py"), os.path.join(SBIN, "el-encryption-facts")]:
            subprocess.run([sys.executable, "-m", "py_compile", s], check=True,
                           env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1",
                                    PYTHONPYCACHEPREFIX=os.path.join(self.tmp, "pyc")))

    def test_executable_bits(self):
        for s in glob.glob(os.path.join(SBIN, "*")) + glob.glob(os.path.join(LIB, "escrow.d", "*")):
            self.assertTrue(os.access(s, os.X_OK), s)

    def test_shellcheck_if_available(self):
        if not shutil.which("shellcheck"):
            self.skipTest("shellcheck not installed")
        p = subprocess.run(["shellcheck", "-x", "-S", "warning"] + BASH_SCRIPTS,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, cwd=ROOT)
        self.assertEqual(p.returncode, 0, p.stdout)


class ConfigLoader(Base):
    def test_config_is_not_executed(self):
        marker = os.path.join(self.tmp, "pwned")
        with open(self.conf, "w") as fh:
            fh.write("EL_ESCROW_BACKEND=$(touch %s)\nPATH=/evil\nnot a line\n"
                     "EL_TPM2_PCRS='7+14'\n" % marker)
        make_device(self.dev, tokens={})
        p = self.run_tool("el-luks-enroll", "--device", self.dev, "--dry-run")
        self.assertFalse(os.path.exists(marker))
        self.assertIn("--tpm2-pcrs=7+14", p.stderr)
        self.assertIn("ignoring invalid config key", p.stderr)

    def test_example_config_parses(self):
        shutil.copy(os.path.join(ROOT, "examples", "encryption.conf.example"), self.conf)
        make_device(self.dev, tokens={})
        pub = "/etc/systemd/tpm2-pcr-public-key.pem"
        p = self.run_tool("el-luks-enroll", "--device", self.dev, "--dry-run",
                          env={"EL_TPM2_PUBLIC_KEY": "", "NEWPIN": ""})
        # inline comments stripped, quoted/unquoted values honoured
        self.assertIn("--tpm2-pcrs=7 ", p.stderr)
        self.assertIn("--tpm2-with-pin=yes", p.stderr)
        self.assertNotIn(pub, p.stderr)   # env (empty) wins over the file
        p = self.run_tool("el-luks-enroll", "--device", self.dev, "--dry-run")
        self.assertIn("--tpm2-public-key=" + pub + " ", p.stderr)


class Enroll(Base):
    def test_dry_run_changes_nothing(self):
        make_device(self.dev, slots={0: "argon2id", 1: "pbkdf2"}, tokens={0: tpm_token(1, pcrs=(0, 7))})
        before = open(self.dev).read()
        ct_before = open(self.crypttab).read()
        p = self.run_tool("el-luks-enroll", "--device", self.dev, "--dry-run", "--json")
        self.assertEqual(open(self.dev).read(), before)
        self.assertEqual(open(self.crypttab).read(), ct_before)
        self.assertIn("[dry-run] systemd-cryptenroll --tpm2-device=auto --tpm2-pcrs=7", p.stderr)
        self.assertIn("--wipe-slot=1", p.stderr)
        self.assertIn("tpm2-device=auto", p.stderr)
        out = json.loads(p.stdout)
        self.assertTrue(out["dry_run"])
        # no mutating calls ran
        for c in self.calls("systemd-cryptenroll"):
            self.assertEqual(c["argv"], ["--version"])

    def test_enroll_replaces_old_slot_after_verification(self):
        make_device(self.dev, slots={0: "argon2id", 1: "pbkdf2"}, tokens={0: tpm_token(1, pcrs=(0, 7))})
        p = self.run_tool("el-luks-enroll", "--device", self.dev, "--json")
        out = json.loads(p.stdout)
        self.assertEqual(out["enrolled_slots"], [2])
        self.assertEqual(out["wiped_slots"], [1])
        d = self.devjson()
        self.assertEqual(sorted(d["keyslots"]), ["0", "2"])
        self.assertEqual(out["state"]["tpm_pcrs"], [7])
        # verification happened before the wipe
        seq = [c["argv"][0] for c in self.calls() if c["cmd"] in ("cryptsetup", "systemd-cryptenroll")
               and c["argv"] and c["argv"][0] in ("open", "--wipe-slot=1")]
        self.assertEqual(seq, ["open", "--wipe-slot=1"])
        ct = open(self.crypttab).read()
        self.assertIn("luks-root\tUUID=%s\tnone\tluks,discard,tpm2-device=auto" % UUID, ct)
        self.assertTrue(glob.glob(self.crypttab + ".el-backup-*"))

    def test_idempotent(self):
        make_device(self.dev, slots={0: "argon2id", 1: "pbkdf2"}, tokens={0: tpm_token(1, pcrs=(7,))})
        p = self.run_tool("el-luks-enroll", "--device", self.dev, "--no-crypttab")
        self.assertIn("already exists", p.stderr)
        self.assertEqual([c for c in self.calls("systemd-cryptenroll") if c["argv"] != ["--version"]], [])

    def test_luks1_refused(self):
        make_device(self.dev, version=1)
        p = self.run_tool("el-luks-enroll", "--device", self.dev, rc=65)
        self.assertIn("LUKS1", p.stderr)

    def test_failed_verification_rolls_back(self):
        make_device(self.dev, slots={0: "argon2id", 1: "pbkdf2"}, tokens={0: tpm_token(1, pcrs=(0, 7))},
                    tpm_ok=False)
        p = self.run_tool("el-luks-enroll", "--device", self.dev, rc=70)
        self.assertIn("failed the unlock test", p.stderr)
        self.assertEqual(sorted(self.devjson()["keyslots"]), ["0", "1"])

    def test_tpm2_pin_from_file_not_leaked(self):
        make_device(self.dev)
        pin = os.path.join(self.tmp, "pin")
        with open(pin, "w") as fh:
            fh.write("S3cretPIN-9931\n")
        p = self.run_tool("el-luks-enroll", "--device", self.dev, "--mode", "tpm2+pin",
                          "--pin-file", pin, "--no-crypttab")
        enroll = [c for c in self.calls("systemd-cryptenroll") if "--tpm2-with-pin=yes" in c["argv"]]
        self.assertEqual(len(enroll), 1)
        self.assertEqual(enroll[0]["env"].get("NEWPIN"), "S3cretPIN-9931")
        self.assertNotIn("S3cretPIN", " ".join(enroll[0]["argv"]))
        self.assertNotIn("S3cretPIN", p.stdout + p.stderr)
        self.assertIn("NEWPIN=<redacted>", p.stderr)
        # pin slots cannot be tested without a terminal -> slot kept, warning shown
        self.assertIn("cannot be tested non-interactively", p.stderr)

    def test_signed_pcr11_policy(self):
        make_device(self.dev)
        pub = os.path.join(self.tmp, "pcr.pem")
        open(pub, "w").write("-----BEGIN PUBLIC KEY-----\n")
        p = self.run_tool("el-luks-enroll", "--device", self.dev, "--tpm2-public-key", pub,
                          "--no-crypttab", "--json")
        out = json.loads(p.stdout)
        self.assertEqual(out["state"]["tpm_signed_pcrs"], [11])
        argv = [c for c in self.calls("systemd-cryptenroll") if c["argv"] != ["--version"]][0]["argv"]
        self.assertIn("--tpm2-public-key=" + pub, argv)
        self.assertIn("--tpm2-public-key-pcrs=11", argv)

    def test_weak_cipher_and_kdf_warned(self):
        make_device(self.dev, cipher="aes-cbc-essiv:sha256", key_size=32, slots={0: "pbkdf2"})
        p = self.run_tool("el-luks-enroll", "--device", self.dev, "--dry-run")
        self.assertIn("data cipher is aes-cbc-essiv:sha256", p.stderr)
        self.assertIn("volume key is 256 bits", p.stderr)
        self.assertIn("keyslot 0 (passphrase) uses kdf pbkdf2", p.stderr)

    def test_tang_requires_pin_thumbprint(self):
        make_device(self.dev)
        self.run_tool("el-luks-enroll", "--device", self.dev, "--mode", "tang",
                      "--tang-url", "https://tang.example", rc=64)
        p = self.run_tool("el-luks-enroll", "--device", self.dev, "--mode", "tang",
                          "--tang-url", "https://tang.example", "--tang-thp", "abc123",
                          "--netdev", "--json")
        out = json.loads(p.stdout)
        self.assertIn("tang", out["state"]["unlock_methods"])
        self.assertIn("_netdev", open(self.crypttab).read())
        bind = self.calls("clevis")[0]["argv"]
        self.assertEqual(bind[-1], '{"url": "https://tang.example", "thp": "abc123"}')

    def test_missing_crypttab_entry_add(self):
        make_device(self.dev)
        open(self.crypttab, "w").close()
        p = self.run_tool("el-luks-enroll", "--device", self.dev, "--crypttab-add", "data")
        self.assertIn("data\tUUID=%s\tnone\tluks,tpm2-device=auto" % UUID, open(self.crypttab).read())
        self.assertNotIn("WARNING: no crypttab", p.stderr)

    def test_regenerate_initrd(self):
        make_device(self.dev)
        self.run_tool("el-luks-enroll", "--device", self.dev, "--regenerate-initrd", "--no-crypttab")
        self.assertTrue(self.calls("dracut"))

    def test_old_systemd_refused(self):
        make_device(self.dev)
        self.run_tool("el-luks-enroll", "--device", self.dev, env={"MOCK_SYSTEMD_VERSION": "250"}, rc=69)


class Escrow(Base):
    def setUp(self):
        super().setUp()
        make_device(self.dev, slots={0: "argon2id", 1: "pbkdf2"}, tokens={0: tpm_token(1)})
        self.filedir = os.path.join(self.tmp, "escrow-files")
        self.write_conf(EL_ESCROW_BACKEND="file", EL_ESCROW_FILE_DIR=self.filedir)

    def key(self):
        return open(os.path.join(self.mockdir, "last-recovery-key")).read()

    def assert_no_leak(self, key, *outputs):
        for o in outputs:
            self.assertNotIn(key, o)
        self.assertNotIn(key, open(self.log).read())
        for root, _, files in os.walk(self.state):
            for f in files:
                if root.startswith(self.filedir):
                    continue
                self.assertNotIn(key, open(os.path.join(root, f)).read(), f)
        run = os.path.join(self.tmp, "run")
        if os.path.isdir(run):
            self.assertEqual(os.listdir(run), [], "secret scratch dir not cleaned")

    def test_escrow_file_backend(self):
        p = self.run_tool("el-recovery-escrow", "escrow", "--device", self.dev, "--json")
        key = self.key()
        self.assert_no_leak(key, p.stdout, p.stderr)
        rec = self.read_state()["volumes"][UUID]
        self.assertEqual(rec["fingerprint_sha256"], hashlib.sha256(key.encode()).hexdigest())
        self.assertEqual(rec["keyslot"], 2)
        self.assertEqual(rec["backend"], "file")
        self.assertTrue(rec["target"].startswith("file:"))
        stored = json.load(open(rec["target"][5:]))
        self.assertEqual(stored["recovery_key"], key)
        self.assertEqual(os.stat(self.filedir).st_mode & 0o777, 0o700)
        self.assertEqual(os.stat(os.path.join(self.state, "escrow.json")).st_mode & 0o777, 0o600)
        # idempotent
        p2 = self.run_tool("el-recovery-escrow", "escrow", "--device", self.dev)
        self.assertIn("already escrowed", p2.stderr)
        st = json.loads(self.run_tool("el-recovery-escrow", "status", "--device", self.dev).stdout)
        self.assertTrue(st[0]["escrowed"])
        self.assertNotIn(key, json.dumps(st))
        v = self.run_tool("el-recovery-escrow", "verify", "--device", self.dev)
        self.assertTrue(json.loads(v.stdout)[0]["backend_verified"])

    def test_rotate_wipes_old_slot(self):
        self.run_tool("el-recovery-escrow", "escrow", "--device", self.dev)
        k1 = self.key()
        p = self.run_tool("el-recovery-escrow", "rotate", "--device", self.dev, "--json")
        k2 = self.key()
        self.assertNotEqual(k1, k2)
        self.assert_no_leak(k2, p.stdout, p.stderr)
        rec = self.read_state()["volumes"][UUID]
        self.assertEqual(rec["fingerprint_sha256"], hashlib.sha256(k2.encode()).hexdigest())
        self.assertEqual(len(rec["history"]), 1)
        d = self.devjson()
        rec_slots = [t["keyslots"] for t in d["tokens"].values() if t["type"] == "systemd-recovery"]
        self.assertEqual(rec_slots, [[str(rec["keyslot"])]])
        self.assertEqual(json.loads(p.stdout)[0]["wiped_slots"], [2])

    def test_rotate_after_use(self):
        self.run_tool("el-recovery-escrow", "escrow", "--device", self.dev)
        p = self.run_tool("el-recovery-escrow", "rotate", "--if-needed", "--device", self.dev)
        self.assertIn("not due", p.stderr)
        self.run_tool("el-recovery-escrow", "mark-used", "--device", self.dev)
        self.assertTrue(self.read_state()["volumes"][UUID]["used"])
        p = self.run_tool("el-recovery-escrow", "rotate", "--if-needed", "--device", self.dev)
        self.assertIn("rotating recovery key (used)", p.stderr)
        self.assertFalse(self.read_state()["volumes"][UUID]["used"])

    def test_preexisting_unescrowed_recovery_slot_is_replaced(self):
        make_device(self.dev, slots={0: "argon2id", 1: "pbkdf2"},
                    tokens={0: {"type": "systemd-recovery", "keyslots": ["1"]}})
        self.run_tool("el-recovery-escrow", "escrow", "--device", self.dev)
        d = self.devjson()
        self.assertEqual(sorted(d["keyslots"]), ["0", "2"])

    def test_backend_failure_removes_new_slot(self):
        tok = os.path.join(self.tmp, "vault-token")
        open(tok, "w").write("hvs.TESTTOKEN")
        self.write_conf(EL_ESCROW_BACKEND="vault", EL_VAULT_ADDR="https://vault.example:8200",
                        EL_VAULT_TOKEN_FILE=tok)
        p = self.run_tool("el-recovery-escrow", "escrow", "--device", self.dev,
                          env={"MOCK_CURL_FAIL": "1"}, rc=75)
        self.assertIn("removing the un-escrowed slot", p.stderr)
        self.assertEqual(sorted(self.devjson()["keyslots"]), ["0", "1"])
        self.assertFalse(os.path.exists(os.path.join(self.state, "escrow.json")))
        self.assert_no_leak(self.key(), p.stdout, p.stderr)

    def test_vault_backend(self):
        tok = os.path.join(self.tmp, "vault-token")
        open(tok, "w").write("hvs.TESTTOKEN\n")
        self.write_conf(EL_ESCROW_BACKEND="vault", EL_VAULT_ADDR="https://vault.example:8200",
                        EL_VAULT_TOKEN_FILE=tok, EL_VAULT_NAMESPACE="it")
        p = self.run_tool("el-recovery-escrow", "escrow", "--device", self.dev,
                          env={"MOCK_EXPECT_TOKEN": "hvs.TESTTOKEN"})
        self.assert_no_leak(self.key(), p.stdout, p.stderr)
        rec = self.read_state()["volumes"][UUID]
        self.assertEqual(rec["target"],
                         "vault:secret/el/luks/4c4c4544004d3510804bc3c04f4e3132/%s#v1" % UUID)
        for c in self.calls("curl"):
            self.assertNotIn("hvs.TESTTOKEN", " ".join(c["argv"]))
            self.assertIn("=https", c["argv"])
        v = self.run_tool("el-recovery-escrow", "verify", "--device", self.dev,
                          env={"MOCK_EXPECT_TOKEN": "hvs.TESTTOKEN"})
        self.assertTrue(json.loads(v.stdout)[0]["backend_verified"])

    def test_vault_rejects_plain_http(self):
        tok = os.path.join(self.tmp, "vault-token")
        open(tok, "w").write("t")
        self.write_conf(EL_ESCROW_BACKEND="vault", EL_VAULT_ADDR="http://vault.example:8200",
                        EL_VAULT_TOKEN_FILE=tok)
        # the mock does not enforce --proto, so assert it is passed
        self.run_tool("el-recovery-escrow", "escrow", "--device", self.dev)
        self.assertTrue(all("=https" in c["argv"] for c in self.calls("curl")))

    def test_azure_managed_identity(self):
        self.write_conf(EL_ESCROW_BACKEND="azure-keyvault", EL_AZURE_KEYVAULT_NAME="corp-kv",
                        EL_AZURE_USE_MANAGED_IDENTITY="1")
        p = self.run_tool("el-recovery-escrow", "escrow", "--device", self.dev,
                          env={"MOCK_EXPECT_TOKEN": "eyJ0eXAiOiJKV1Qi.mi"})
        self.assert_no_leak(self.key(), p.stdout, p.stderr)
        rec = self.read_state()["volumes"][UUID]
        self.assertEqual(rec["target"],
                         "azure-keyvault:https://corp-kv.vault.azure.net/secrets/luks-%s/0123abcd" % UUID)
        for c in self.calls("curl"):
            self.assertNotIn("eyJ0eXAiOiJKV1Qi", " ".join(c["argv"]))

    def test_webhook_ack_required(self):
        tok = os.path.join(self.tmp, "mdm-token")
        open(tok, "w").write("mdm-bearer-1")
        self.write_conf(EL_ESCROW_BACKEND="webhook", EL_WEBHOOK_URL="https://mdm.example/escrow",
                        EL_WEBHOOK_TOKEN_FILE=tok, EL_WEBHOOK_CLIENT_CERT="/etc/el/dev.crt",
                        EL_WEBHOOK_CLIENT_KEY="/etc/el/dev.key",
                        EL_WEBHOOK_VERIFY_URL="https://mdm.example/escrow/{uuid}")
        self.run_tool("el-recovery-escrow", "escrow", "--device", self.dev,
                      env={"MOCK_WEBHOOK_BAD_ACK": "1"}, rc=75)
        self.assertEqual(sorted(self.devjson()["keyslots"]), ["0", "1"])
        p = self.run_tool("el-recovery-escrow", "escrow", "--device", self.dev)
        self.assert_no_leak(self.key(), p.stdout, p.stderr)
        self.assertEqual(self.read_state()["volumes"][UUID]["target"], "webhook:mdm-escrow-42")
        argv = self.calls("curl")[-1]["argv"]
        self.assertIn("--cert", argv)
        v = self.run_tool("el-recovery-escrow", "verify", "--device", self.dev)
        self.assertTrue(json.loads(v.stdout)[0]["backend_verified"])

    def test_fallback_generator(self):
        p = self.run_tool("el-recovery-escrow", "escrow", "--device", self.dev, "--fallback")
        rec = self.read_state()["volumes"][UUID]
        stored = json.load(open(rec["target"][5:]))["recovery_key"]
        self.assertRegex(stored, r"^[cbdefghijklnrtuv]{8}(-[cbdefghijklnrtuv]{8}){7}$")
        self.assertNotIn(stored, p.stdout + p.stderr)
        d = self.devjson()
        self.assertIn({"type": "el-recovery", "keyslots": [str(rec["keyslot"])]}, d["tokens"].values())
        self.assertEqual(self.devjson()["_mock"]["added_keys"], [71])  # no trailing newline

    def test_dry_run(self):
        before = open(self.dev).read()
        p = self.run_tool("el-recovery-escrow", "rotate", "--device", self.dev, "--dry-run")
        self.assertEqual(open(self.dev).read(), before)
        self.assertIn("[dry-run] systemd-cryptenroll --recovery-key", p.stderr)
        self.assertFalse(os.path.exists(os.path.join(self.state, "escrow.json")))

    def test_discovers_devices_via_lsblk(self):
        tree = {"blockdevices": [{"name": self.dev, "path": self.dev, "type": "part",
                                  "fstype": "crypto_LUKS", "uuid": UUID}]}
        lj = os.path.join(self.tmp, "lsblk.json")
        json.dump(tree, open(lj, "w"))
        self.run_tool("el-recovery-escrow", "escrow", env={"MOCK_LSBLK_JSON": lj})
        self.assertIn(UUID, self.read_state()["volumes"])


class CryptoErase(Base):
    def setUp(self):
        super().setUp()
        make_device(self.dev, slots={0: "argon2id", 1: "pbkdf2"}, tokens={0: tpm_token(1)})
        if not shutil.which("openssl"):
            self.skipTest("openssl not available")
        self.key = os.path.join(self.tmp, "mdm.key")
        self.pub = os.path.join(self.tmp, "mdm.pub.pem")
        self.genkey("EC")

    def genkey(self, kind):
        if kind == "ED25519":
            subprocess.run(["openssl", "genpkey", "-algorithm", "ED25519", "-out", self.key], check=True,
                           stderr=subprocess.DEVNULL)
        else:
            subprocess.run(["openssl", "genpkey", "-algorithm", "EC", "-pkeyopt",
                            "ec_paramgen_curve:P-256", "-out", self.key], check=True,
                           stderr=subprocess.DEVNULL)
        subprocess.run(["openssl", "pkey", "-in", self.key, "-pubout", "-out", self.pub], check=True)
        self.kind = kind

    def token(self, **over):
        now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
        t = {"action": "device.crypto-erase", "machine_id": "4c4c4544004d3510804bc3c04f4e3132",
             "luks_uuids": [UUID], "nonce": base64.b16encode(os.urandom(12)).decode(),
             "issued_at": (now - dt.timedelta(minutes=1)).isoformat().replace("+00:00", "Z"),
             "expires_at": (now + dt.timedelta(minutes=20)).isoformat().replace("+00:00", "Z")}
        t.update(over)
        tp = os.path.join(self.tmp, "token.json")
        sp = os.path.join(self.tmp, "token.sig")
        with open(tp, "w") as fh:
            json.dump(t, fh)
        if self.kind == "ED25519":
            cmd = ["openssl", "pkeyutl", "-sign", "-inkey", self.key, "-rawin", "-in", tp, "-out", sp]
        else:
            cmd = ["openssl", "dgst", "-sha256", "-sign", self.key, "-out", sp, tp]
        subprocess.run(cmd, check=True)
        return tp, sp

    def erase(self, tp, sp, *extra, rc=0):
        return self.run_tool("el-crypto-erase", "--token", tp, "--signature", sp,
                             "--pubkey", self.pub, "--device", self.dev, *extra, rc=rc)

    def test_dry_run_is_default(self):
        tp, sp = self.token()
        p = self.erase(tp, sp)
        self.assertIn("DRY RUN", p.stderr)
        self.assertIn("[dry-run] cryptsetup luksErase -q", p.stderr)
        self.assertEqual(len(self.devjson()["keyslots"]), 2)

    def test_execute_needs_yes(self):
        tp, sp = self.token()
        self.erase(tp, sp, "--execute", rc=64)
        self.assertEqual(len(self.devjson()["keyslots"]), 2)

    def test_execute_erases_and_blocks_replay(self):
        tp, sp = self.token()
        p = self.erase(tp, sp, "--execute", "--yes", "--json", "--reboot")
        self.assertEqual(self.devjson()["keyslots"], {})
        self.assertEqual(json.loads(p.stdout)[0]["remaining_keyslots"], "0")
        self.assertTrue(self.calls("systemctl"))
        make_device(self.dev)
        p = self.erase(tp, sp, "--execute", "--yes", rc=77)
        self.assertIn("replay", p.stderr)

    def test_ed25519(self):
        self.genkey("ED25519")
        tp, sp = self.token()
        self.erase(tp, sp, "--execute", "--yes")
        self.assertEqual(self.devjson()["keyslots"], {})

    def test_bad_signature(self):
        tp, sp = self.token()
        with open(tp, "a") as fh:
            fh.write(" ")
        p = self.erase(tp, sp, "--execute", "--yes", rc=77)
        self.assertIn("signature verification FAILED", p.stderr)
        self.assertEqual(len(self.devjson()["keyslots"]), 2)

    def test_wrong_key(self):
        tp, sp = self.token()
        self.genkey("EC")  # replaces the pinned public key
        self.erase(tp, sp, "--execute", "--yes", rc=77)

    def test_claims(self):
        for over, msg in [({"machine_id": "other"}, "machine_id"),
                          ({"luks_uuids": ["nope"]}, "does not cover"),
                          ({"action": "device.wipe"}, "action"),
                          ({"nonce": "short"}, "nonce"),
                          ({"expires_at": "2020-01-01T00:00:00Z"}, "expired")]:
            tp, sp = self.token(**over)
            p = self.erase(tp, sp, "--execute", "--yes", rc=77)
            self.assertIn(msg, p.stderr)
        self.assertEqual(len(self.devjson()["keyslots"]), 2)

    def test_wildcard_uuid(self):
        tp, sp = self.token(luks_uuids=["*"])
        self.erase(tp, sp, "--execute", "--yes")


class Reseal(Base):
    def test_uki_update_with_signed_policy_needs_nothing(self):
        make_device(self.dev, slots={0: "argon2id", 1: "pbkdf2"}, tokens={0: tpm_token(1, (7,), (11,))})
        p = self.run_tool("el-tpm-reseal", "pre-update", "--kind", "uki", "--device", self.dev, "--json")
        self.assertEqual(json.loads(p.stdout)[0]["reason"], "not-affected")

    def test_dbx_update_without_strategy_warns(self):
        make_device(self.dev, slots={0: "argon2id", 1: "pbkdf2"}, tokens={0: tpm_token(1, (7,))})
        p = self.run_tool("el-tpm-reseal", "pre-update", "--kind", "dbx", "--device", self.dev, rc=2)
        self.assertIn("expect a recovery-key prompt", p.stderr)

    def test_predict_then_confirm(self):
        make_device(self.dev, slots={0: "argon2id", 1: "pbkdf2"}, tokens={0: tpm_token(1, (7,))})
        h = "ab" * 32
        self.run_tool("el-tpm-reseal", "pre-update", "--kind", "dbx", "--device", self.dev,
                      "--predicted-pcrs", "7:sha256=" + h)
        d = self.devjson()
        self.assertEqual(sorted(d["keyslots"]), ["0", "1", "2"])
        pred = [t for t in d["tokens"].values() if t.get("mock_predicted")]
        self.assertEqual(pred[0]["mock_predicted"], "7:sha256=" + h)
        st = json.load(open(os.path.join(self.state, "reseal.json")))
        self.assertTrue(st[UUID]["pending"])
        p = self.run_tool("el-tpm-reseal", "post-update", "--device", self.dev, "--json")
        self.assertEqual(json.loads(p.stdout)[0]["action"], "confirmed-prediction")
        self.assertEqual(sorted(self.devjson()["keyslots"]), ["0", "2"])
        self.assertEqual(json.load(open(os.path.join(self.state, "reseal.json"))), {})

    def test_bridge_then_reseal(self):
        make_device(self.dev, slots={0: "argon2id", 1: "pbkdf2"}, tokens={0: tpm_token(1, (7,), (11,))})
        pub = os.path.join(self.tmp, "pcr.pem")
        open(pub, "w").write("x")
        env = {"EL_RESEAL_ALLOW_BRIDGE": "1", "EL_TPM2_PUBLIC_KEY": pub}
        self.run_tool("el-tpm-reseal", "pre-update", "--kind", "firmware", "--device", self.dev, env=env)
        d = self.devjson()
        bridge = [t for t in d["tokens"].values() if t["keyslots"] == ["2"]][0]
        self.assertEqual(bridge["tpm2-pcrs"], [])
        self.assertEqual(bridge["tpm2_pubkey_pcrs"], [11])
        self.run_tool("el-tpm-reseal", "post-update", "--device", self.dev, env=env)
        d = self.devjson()
        self.assertEqual(sorted(d["keyslots"]), ["0", "3"])
        self.assertEqual(d["tokens"][next(iter(d["tokens"]))]["tpm2-pcrs"], [7])

    def test_post_update_without_pending_is_noop(self):
        make_device(self.dev, slots={0: "argon2id", 1: "pbkdf2"}, tokens={0: tpm_token(1, (7,))})
        p = self.run_tool("el-tpm-reseal", "post-update", "--device", self.dev)
        self.assertIn("no pending", p.stderr)

    def test_dry_run(self):
        make_device(self.dev, slots={0: "argon2id", 1: "pbkdf2"}, tokens={0: tpm_token(1, (7,))})
        before = open(self.dev).read()
        p = self.run_tool("el-tpm-reseal", "pre-update", "--kind", "dbx", "--device", self.dev,
                          "--predicted-pcrs", "7:sha256=" + "cd" * 32, "--dry-run")
        self.assertEqual(open(self.dev).read(), before)
        self.assertIn("[dry-run] systemd-cryptenroll --tpm2-device=auto --tpm2-pcrs=7:sha256=", p.stderr)


class Facts(Base):
    def lsblk(self, extra=()):
        tree = {"blockdevices": [{
            "name": "/dev/nvme0n1", "path": "/dev/nvme0n1", "type": "disk", "fstype": None,
            "uuid": None, "mountpoints": [None], "children": [
                {"name": "/dev/nvme0n1p1", "path": "/dev/nvme0n1p1", "type": "part",
                 "fstype": "vfat", "uuid": "AB12", "mountpoints": ["/boot/efi"]},
                {"name": self.dev, "path": self.dev, "type": "part", "fstype": "crypto_LUKS",
                 "uuid": UUID, "mountpoints": [None], "children": [
                     {"name": "/dev/mapper/luks-root", "path": "/dev/mapper/luks-root",
                      "type": "crypt", "fstype": "btrfs", "uuid": "f00",
                      "mountpoints": ["/", "/home"]}]}]}] + list(extra)}
        p = os.path.join(self.tmp, "lsblk.json")
        json.dump(tree, open(p, "w"))
        return p

    def test_facts_shape(self):
        make_device(self.dev, slots={0: "argon2id", 1: "pbkdf2", 2: "pbkdf2"},
                    tokens={0: tpm_token(1, (7,), (11,), pin=True),
                            1: {"type": "systemd-recovery", "keyslots": ["2"]}})
        p = self.run_tool("el-encryption-facts", env={"MOCK_LSBLK_JSON": self.lsblk()})
        f = json.loads(p.stdout)["encryption"]
        v = f["volumes"][0]
        self.assertEqual(v["device"], self.dev)
        self.assertEqual(v["status"], "encrypted")
        self.assertEqual(v["cipher"], "aes-xts-plain64-512")
        self.assertEqual(v["unlock_methods"], ["passphrase", "recovery-key", "tpm2+pin"])
        self.assertEqual(v["tpm_pcrs"], [7])
        self.assertEqual(v["tpm_signed_pcrs"], [11])
        self.assertTrue(v["opened"])
        self.assertEqual(v["mountpoints"], ["/", "/home"])
        self.assertTrue(f["root_encrypted"])
        self.assertEqual(f["unencrypted_mounts"], [])
        self.assertEqual(f["recovery"], {"escrowed": False, "escrow_target": None,
                                         "last_rotated": None, "rotation_pending": False})
        self.assertNotIn("AAAA", p.stdout)  # no tpm2 blob

    def test_facts_after_escrow_and_unencrypted_mount(self):
        make_device(self.dev)
        self.write_conf(EL_ESCROW_BACKEND="file", EL_ESCROW_FILE_DIR=os.path.join(self.tmp, "ef"))
        self.run_tool("el-recovery-escrow", "escrow", "--device", self.dev)
        extra = [{"name": "/dev/sdb1", "path": "/dev/sdb1", "type": "part", "fstype": "ext4",
                  "uuid": "u", "mountpoints": ["/srv/data"]}]
        p = self.run_tool("el-encryption-facts", "--compact", env={"MOCK_LSBLK_JSON": self.lsblk(extra)})
        f = json.loads(p.stdout)["encryption"]
        self.assertTrue(f["recovery"]["escrowed"])
        self.assertTrue(f["recovery"]["escrow_target"].startswith("file:"))
        self.assertIsNotNone(f["recovery"]["last_rotated"])
        self.assertEqual(f["unencrypted_mounts"], ["/srv/data"])

    def test_luks1_reported(self):
        make_device(self.dev, version=1)
        p = self.run_tool("el-encryption-facts", env={"MOCK_LSBLK_JSON": self.lsblk()})
        self.assertEqual(json.loads(p.stdout)["encryption"]["volumes"][0]["status"], "encrypted-luks1")


class Library(unittest.TestCase):
    def setUp(self):
        sys.path.insert(0, LIB)
        import elcrypt
        self.e = elcrypt

    def test_crypttab_preserves_other_lines(self):
        text = "# c\nswap /dev/sda2 /dev/urandom swap\nroot UUID=%s none luks,tpm2-device=/dev/tpmrm0,tpm2-pcrs=0+7\n" % UUID
        new, info = self.e.compute_crypttab(text, UUID, "", "", "fido2")
        self.assertTrue(info["changed"])
        self.assertIn("swap /dev/sda2 /dev/urandom swap", new)
        self.assertIn("root\tUUID=%s\tnone\tluks,fido2-device=auto" % UUID, new)
        new2, info2 = self.e.compute_crypttab(new, UUID, "", "", "fido2")
        self.assertFalse(info2["changed"])

    def test_claims_future_token(self):
        now = self.e.utcnow()
        t = {"action": "device.crypto-erase", "machine_id": "m", "luks_uuids": ["*"],
             "nonce": "x" * 16, "issued_at": self.e.isoformat(now + dt.timedelta(hours=1)),
             "expires_at": self.e.isoformat(now + dt.timedelta(hours=1, minutes=5))}
        self.assertIn("issued_at is in the future", self.e.check_erase_claims(t, "m", ["u"]))

    def test_clevis_token_decoding(self):
        hdr = base64.urlsafe_b64encode(b'{"clevis":{"pin":"sss"}}').decode().rstrip("=")
        meta = {"keyslots": {"0": {"key_size": 64, "kdf": {"type": "pbkdf2"}}},
                "tokens": {"0": {"type": "clevis", "keyslots": ["0"], "jwe": {"protected": hdr}}},
                "segments": {"0": {"encryption": "aes-xts-plain64"}}}
        self.assertEqual(self.e.summarize_luks(meta)["unlock_methods"], ["clevis-sss"])


if __name__ == "__main__":
    unittest.main(verbosity=2 if "-v" in sys.argv else 1,
                  argv=[a for a in sys.argv if a != "-v"])
