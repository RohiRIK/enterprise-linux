import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _helpers import deep, example_policy  # noqa: E402

from elperm.naming import GroupNamer, slugify  # noqa: E402
from elperm.policy import validate_policy  # noqa: E402
from elperm.util import PolicyError, parse_duration, safe_file_token  # noqa: E402


class PolicyValidationTests(unittest.TestCase):
    def test_example_is_valid(self):
        p = validate_policy(example_policy())
        self.assertEqual(p.name, "default-laptops")
        self.assertEqual(p.max_jit_seconds, 3600)
        self.assertFalse(p.roles["power-user"]["enabled"])
        self.assertFalse(p.roles["user"]["elevated"])
        self.assertTrue(p.roles["helpdesk"]["elevated"])

    def test_schema_rejects_unknown_property(self):
        doc = example_policy()
        doc["spec"]["roles"]["local-admin"]["sudoo"] = {}
        with self.assertRaisesRegex(PolicyError, "unexpected property 'sudoo'"):
            validate_policy(doc)

    def test_schema_rejects_bad_group_ref(self):
        doc = example_policy()
        doc["spec"]["login"]["allow"] = ["okta:group:Everyone"]
        with self.assertRaisesRegex(PolicyError, "schema"):
            validate_policy(doc)

    def test_nopasswd_requires_explicit_opt_in(self):
        doc = example_policy()
        doc["spec"]["roles"]["local-admin"]["sudo"]["nopasswd"] = True
        with self.assertRaisesRegex(PolicyError, "allowNopasswd"):
            validate_policy(doc)
        doc["spec"]["sudo"]["allowNopasswd"] = True
        validate_policy(doc)

    def test_user_role_cannot_have_sudo(self):
        doc = example_policy()
        doc["spec"]["roles"]["user"]["sudo"] = {"commands": ["ALL"]}
        with self.assertRaisesRegex(PolicyError, "roles.user must not grant sudo"):
            validate_policy(doc)

    def test_allow_and_deny_overlap_rejected(self):
        doc = example_policy()
        doc["spec"]["login"]["deny"].append("entra:group:All-Employees")
        with self.assertRaisesRegex(PolicyError, "both allow and deny"):
            validate_policy(doc)

    def test_default_duration_above_max_rejected(self):
        doc = example_policy()
        doc["spec"]["jit"]["defaultDuration"] = "2h"
        with self.assertRaisesRegex(PolicyError, "defaultDuration exceeds"):
            validate_policy(doc)

    def test_sudoers_special_chars_in_command_rejected(self):
        doc = example_policy()
        doc["spec"]["roles"]["helpdesk"]["sudo"]["commands"] = ["/bin/sh -c a,b"]
        with self.assertRaises(PolicyError):
            validate_policy(doc)

    def test_group_name_collision_rejected(self):
        doc = example_policy()
        doc["spec"]["roles"]["helpdesk"]["groups"] = ["entra:group:IT Linux Admins"]
        with self.assertRaisesRegex(PolicyError, "both map to 'it-linux-admins'"):
            validate_policy(deep(doc))


class NamingTests(unittest.TestCase):
    def test_slug(self):
        self.assertEqual(slugify("IT Linux Admins"), "it-linux-admins")
        self.assertEqual(slugify("123 Group"), "g123-group")

    def test_override_and_truncation_deterministic(self):
        n = GroupNamer({"sources": {"entra": {"template": "{slug}", "maxLength": 16}},
                        "overrides": {"entra:group:X": "custom-x"}})
        self.assertEqual(n.posix_name("entra:group:X"), "custom-x")
        a = n.posix_name("entra:group:A Very Long Group Name Indeed")
        self.assertLessEqual(len(a), 16)
        self.assertEqual(a, n.posix_name("entra:group:A Very Long Group Name Indeed"))
        self.assertNotEqual(a, n.posix_name("entra:group:A Very Long Group Name Too"))

    def test_template_prefix(self):
        n = GroupNamer({"sources": {"ad": {"template": "ad-{slug}"}}})
        self.assertEqual(n.posix_name("ad:group:Domain Admins"), "ad-domain-admins")

    def test_local_name_verbatim_and_validated(self):
        n = GroupNamer(None)
        self.assertEqual(n.posix_name("local:group:wheel"), "wheel")
        with self.assertRaises(PolicyError):
            n.posix_name("local:group:Bad Name")


class UtilTests(unittest.TestCase):
    def test_durations(self):
        self.assertEqual(parse_duration("30m"), 1800)
        self.assertEqual(parse_duration("2h"), 7200)
        self.assertEqual(parse_duration("90s"), 90)
        self.assertEqual(parse_duration("15"), 900)
        with self.assertRaises(Exception):
            parse_duration("soon")

    def test_safe_file_token_has_no_dot(self):
        t = safe_file_token("alice@corp.example")
        self.assertNotIn(".", t)
        self.assertNotIn("@", t)
        self.assertEqual(safe_file_token("bob"), "bob")


if __name__ == "__main__":
    unittest.main()
