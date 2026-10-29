"""Shared helpers for the fake cryptsetup / systemd-cryptenroll / clevis /
lsblk / curl used by the test-suite. A "device" is a plain JSON file holding
LUKS2 metadata in the shape of `cryptsetup luksDump --dump-json-metadata`
plus a private "_mock" section. Nothing here touches real block devices."""
import json
import os
import sys


def log_call(name):
    path = os.environ.get("MOCK_LOG")
    if path:
        with open(path, "a") as fh:
            fh.write(json.dumps({"cmd": name, "argv": sys.argv[1:],
                                 "env": {k: os.environ.get(k, "") for k in
                                         ("NEWPIN", "PASSWORD", "NEWPASSWORD")
                                         if os.environ.get(k)}}) + "\n")


def load_dev(path):
    with open(path) as fh:
        return json.load(fh)


def save_dev(path, d):
    with open(path, "w") as fh:
        json.dump(d, fh, indent=1)


def public(d):
    return {k: v for k, v in d.items() if k != "_mock"}


def next_slot(d):
    used = {int(k) for k in d["keyslots"]}
    i = 0
    while i in used:
        i += 1
    return i


def next_token(d):
    used = {int(k) for k in d["tokens"]}
    i = 0
    while i in used:
        i += 1
    return i


def add_slot(d, kdf="pbkdf2", token=None):
    s = next_slot(d)
    d["keyslots"][str(s)] = {
        "type": "luks2", "key_size": 64,
        "area": {"type": "raw", "encryption": "aes-xts-plain64", "key_size": 64},
        "kdf": {"type": kdf},
    }
    if token is not None:
        token = dict(token, keyslots=[str(s)])
        d["tokens"][str(next_token(d))] = token
    return s


def remove_slots(d, slots):
    slots = {str(s) for s in slots}
    for s in slots:
        d["keyslots"].pop(s, None)
    for tid in list(d["tokens"]):
        ks = [k for k in d["tokens"][tid].get("keyslots", []) if k not in slots]
        if not ks:
            del d["tokens"][tid]
        else:
            d["tokens"][tid]["keyslots"] = ks
