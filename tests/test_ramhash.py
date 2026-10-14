import hashlib
import os
import tempfile
import unittest

import ramhash
from ramhash import ram1024


class DigestTests(unittest.TestCase):
    def test_default_is_hedged_ram_plus_sha3(self):
        d = ramhash.digest(b"abc")
        _, ver, alg, hexd = d.split("$")
        self.assertEqual((ver, alg), ("rh1", "ram-1024+sha3-512"))
        expected = (ram1024.ram_hash(b"abc").hex()
                    + hashlib.sha3_512(b"abc").hexdigest())
        self.assertEqual(hexd, expected)
        self.assertEqual(len(hexd), 384)  # 1024 + 512 bits

    def test_ram1024_streaming_matches_oneshot(self):
        data = os.urandom(1000)
        for cls in (ramhash.Ram1024, ram1024.Ram1024):
            h = cls()
            for i in range(0, 1000, 37):
                h.update(data[i:i + 37])
            self.assertEqual(h.digest(), ram1024.ram_hash(data))
            self.assertEqual(h.digest(), h.digest())  # digest() is repeatable

    def test_known_answer_sha3_512(self):
        # NIST FIPS 202 test vector for "abc"
        self.assertTrue(ramhash.digest("abc", "sha3-512").endswith(
            "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e"
            "10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"))

    def test_str_and_bytes_agree(self):
        self.assertEqual(ramhash.digest("héllo"), ramhash.digest("héllo".encode()))

    def test_avalanche(self):
        a = int(ramhash.digest(b"hello").split("$")[3], 16)
        b = int(ramhash.digest(b"hellp").split("$")[3], 16)
        flipped = bin(a ^ b).count("1")
        self.assertTrue(650 < flipped < 886, flipped)  # ~half of 1536 bits

    def test_file_matches_bytes(self):
        data = os.urandom(3 * (1 << 20) + 7)
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(data)
        try:
            self.assertEqual(ramhash.digest_file(f.name), ramhash.digest(data))
        finally:
            os.unlink(f.name)

    def test_unknown_alg_rejected(self):
        with self.assertRaises(ValueError):
            ramhash.digest(b"x", "md5")


class VerifyAndMigrationTests(unittest.TestCase):
    def test_verify(self):
        d = ramhash.digest(b"data")
        self.assertTrue(ramhash.verify(b"data", d))
        self.assertFalse(ramhash.verify(b"Data", d))

    def test_legacy_sha256_only_with_opt_in(self):
        legacy = hashlib.sha256(b"data").hexdigest()
        self.assertFalse(ramhash.verify(b"data", legacy))  # no silent downgrade
        self.assertFalse(ramhash.verify(b"data", "$rh1$sha256$" + legacy))
        self.assertTrue(ramhash.verify(b"data", legacy, allow_legacy=True))
        self.assertTrue(ramhash.needs_rehash(legacy))
        self.assertFalse(ramhash.needs_rehash(ramhash.digest(b"data")))

    def test_malformed_input_returns_false(self):
        for bad in ("", "$", "$rh1$", "$rh1$nope$00", "$rh9$sha3-512$00", "é" * 64, None, 5):
            self.assertFalse(ramhash.verify(b"x", bad))


class KeyedTests(unittest.TestCase):
    def test_hmac(self):
        t = ramhash.keyed_digest(b"k", b"msg")
        self.assertTrue(ramhash.verify_keyed(b"k", b"msg", t))
        self.assertFalse(ramhash.verify_keyed(b"k2", b"msg", t))
        self.assertFalse(ramhash.verify_keyed(b"k", b"msg2", t))


class PasswordTests(unittest.TestCase):
    SMALL = dict(memory_kib=256, time_cost=1, lanes=2)

    def test_roundtrip_and_salting(self):
        a = ramhash.hash_password("correct horse", **self.SMALL)
        b = ramhash.hash_password("correct horse", **self.SMALL)
        self.assertTrue(a.startswith("$rh1$ram-balloon2$m=256,t=1,p=2$"))
        self.assertNotEqual(a, b)  # random salt
        self.assertTrue(ramhash.verify_password("correct horse", a))
        self.assertFalse(ramhash.verify_password("wrong", a))
        self.assertFalse(ramhash.verify_password("x", "garbage"))

    def test_default_is_memory_hard(self):
        h = ramhash.hash_password("pw")  # one full-cost hash (~1 s); the
        self.assertIn("$ram-balloon2$m=16384,t=3,p=4$", h)  # round trip is
        self.assertFalse(ramhash.needs_rehash_password(h))  # tested small

    def test_pbkdf2_still_verifies_and_is_flagged(self):
        old = ramhash._hash_password_pbkdf2("pw", b"s" * 16, 1000)
        self.assertTrue(ramhash.verify_password("pw", old))
        self.assertFalse(ramhash.verify_password("pw2", old))
        self.assertTrue(ramhash.needs_rehash_password(old))

    def test_attacker_chosen_cost_refused(self):
        """A planted stored hash must not make verification hang (DoS)."""
        salt = "00" * 16
        for evil in ("$rh1$pbkdf2-sha512$999999999999$00$00",
                     "$rh1$ram-balloon2$m=99999999,t=1,p=1$%s$%s" % (salt, "00" * 32),
                     "$rh1$ram-balloon2$m=1024,t=1000,p=1$%s$%s" % (salt, "00" * 32),
                     "$rh1$ram-balloon2$m=1024,t=1,p=1000$%s$%s" % (salt, "00" * 32),
                     "$rh1$ram-balloon2$m=1024,t=1,p=1,x=1$%s$%s" % (salt, "00" * 32),
                     "$rh1$ram-balloon2$m=1024,t=1,p=1$00$%s" % ("00" * 32),
                     "$rh1$ram-balloon2$m=1024,t=1,p=1$%s$00" % salt,
                     "$rh1$scrypt$x$00$00", None, 42):
            self.assertFalse(ramhash.verify_password("x", evil), evil)

    def test_review_findings(self):
        """Independent review (round 10): malleability, cost caps, bad params."""
        good = ramhash.hash_password("pw", **self.SMALL)
        self.assertTrue(ramhash.verify_password("pw", good))
        salt, dk = good.split("$")[4:]
        for evil in ("$rh1$ram-balloon2$m=+256,t=1,p=2$%s$%s" % (salt, dk),
                     "$rh1$ram-balloon2$m=2_56,t=1,p=2$%s$%s" % (salt, dk),
                     "$rh1$ram-balloon2$m=256,t= 1,p=2$%s$%s" % (salt, dk),
                     "$rh1$ram-balloon2$m=0256,t=1,p=2$%s$%s" % (salt, dk),
                     "$rh1$ram-balloon2$m=256,t=1,p=2$%s$%s" % (salt.upper(), dk),
                     "$rh1$ram-balloon2$m=256,t=1,p=2$%s $%s" % (salt, dk),
                     "$rh1$ram-balloon$m=256,t=1,p=2$%s$%s" % (salt, dk),  # v1 id
                     "$rh1$ram-balloon2$m=131072,t=4,p=16$%s$%s" % (salt, dk),  # cost cap
                     "$rh1$pbkdf2-sha512$1000$%s$%s" % ("00" * 16, "00" * 3200)):
            self.assertFalse(ramhash.verify_password("pw", evil), evil)
        self.assertTrue(ramhash.needs_rehash_password(
            "$rh1$ram-balloon$m=16384,t=3,p=4$%s$%s" % (salt, dk)))
        for bad in (dict(memory_kib=2 ** 32 + 256, time_cost=1, lanes=2),
                    dict(memory_kib=256, time_cost=-1, lanes=2),
                    dict(memory_kib=256, time_cost=1.0, lanes=2),
                    dict(memory_kib=256, time_cost=1, lanes=17),
                    dict(memory_kib=1 << 20, time_cost=2, lanes=4)):
            with self.assertRaises((ValueError, TypeError)):
                ramhash.hash_password("pw", **bad)
        self.assertFalse(ramhash.verify_keyed(b"k", b"m", "\u00e9"))
        # re-review of round 10
        for evil in ("JUNK" + good,
                     ):
            self.assertFalse(ramhash.verify_password("pw", evil), evil)
        for over in ("m=65536,t=2,p=1", "m=6144,t=64,p=1", "m=131072,t=1,p=4"):
            with self.assertRaises(ValueError):  # refused before any work
                ramhash._parse_balloon(over)
        for ok in ("m=16384,t=3,p=4", "m=65536,t=1,p=1"):
            ramhash._parse_balloon(ok)
        self.assertFalse(ramhash.verify_password(2 ** 64, good))
        self.assertFalse(ramhash.verify_password(10 ** 9, good))  # no 1 GB allocation
        self.assertFalse(ramhash.verify_keyed("\ud800", "x", "y"))
        self.assertFalse(ramhash.verify_keyed(2 ** 64, "x", "y"))
        with self.assertRaises(TypeError):
            ramhash.hash_password(5)
        self.assertTrue(ramhash.needs_rehash_password("JUNK" + good))
        weak = ramhash._hash_password_pbkdf2("pw", b"s" * 16, 1)
        self.assertTrue(ramhash.verify_password("pw", weak))
        self.assertTrue(ramhash.needs_rehash_password(weak))
        with self.assertRaises(ValueError):
            ramhash.hash_parallel(b"x" * 70000, gpu=True, gpu_share=4.0)
        with self.assertRaises(ValueError):
            ramhash.hash_parallel(b"x" * 70000, gpu=True, gpu_share=float("nan"))

    def test_matches_reference(self):
        """The fast library reproduces tests/kat_pwhash.txt (made by the pure-
        Python reference; `make reference` regenerates and diffs it), incl.
        the 2- and 3-lane cases with cross-lane reads."""
        from ramhash import _fast
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "kat_pwhash.txt")
        msg = lambda n: bytes((7 * i * i + 13 * i + 1) % 256 for i in range(n))
        key = lambda n: bytes((31 * i + 0xA5) % 256 for i in range(n))
        n = 0
        with open(path) as f:
            lines = f.read().splitlines()
        for line in lines:
            if line.startswith("#") or not line.strip():
                continue
            outlen, m, t, p, pl, sl, hexd = line.split()
            got = _fast.pwhash(msg(int(pl)), key(int(sl)), int(outlen), int(m), int(t), int(p))
            self.assertEqual(got.hex(), hexd, line)
            n += 1
        self.assertGreaterEqual(n, 5)


if __name__ == "__main__":
    unittest.main()
