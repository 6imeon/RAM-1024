import ctypes
import hashlib
import itertools
import os
import unittest

from ramhash import _fast, lab, ram1024

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")


class LabMatchesRealAlgorithms(unittest.TestCase):
    """Full-round lab cores must equal the real standardized hashes, so the
    reduced-round comparisons are against the genuine designs."""

    def test_sha256(self):
        for _ in range(20):
            m = os.urandom(55)
            block = m + b"\x80" + (55 * 8).to_bytes(8, "big")
            self.assertEqual(lab.core(lab.SHA256, 64, block),
                             hashlib.sha256(m).digest())

    def test_sha3_512(self):
        for _ in range(20):
            m = os.urandom(64)
            self.assertEqual(lab.core(lab.SHA3_512, 24, m),
                             hashlib.sha3_512(m).digest()[:32])

    def test_blake2b(self):
        for _ in range(20):
            m = os.urandom(64)
            self.assertEqual(lab.core(lab.BLAKE2B, 12, m),
                             hashlib.blake2b(m, digest_size=64).digest()[:32])


class Ram1024(unittest.TestCase):
    def test_c_matches_python_reference(self):
        for n in [0, 1, 63, 64, 127, 128, 129, 255, 256, 1000]:
            m = os.urandom(n)
            for outlen in (32, 64, 200):
                self.assertEqual(lab.ram_hash(m, outlen),
                                 ram1024.ram_hash(m, outlen), (n, outlen))
        key = os.urandom(32)
        self.assertEqual(lab.ram_hash(b"msg", 64, ram1024.MODE_MAC, key=key),
                         ram1024.ram_hash(b"msg", 64, ram1024.MODE_MAC, key=key))

    def test_chi3_is_bijective(self):
        outs = set()
        for x, y, z in itertools.product((0, 1), repeat=3):
            outs.add((x ^ (~y & z & 1), y ^ (~z & x & 1), z ^ (~x & y & 1)))
        self.assertEqual(len(outs), 8)

    def test_permutation_is_invertible_on_samples(self):
        # chi3 + G are bijections, so distinct states never collide.
        seen = set()
        for i in range(2000):
            s = [0] * 32
            s[i % 32] = i
            ram1024.permute(s, 4)
            seen.add(tuple(s))
        self.assertEqual(len(seen), 2000)

    def test_domain_separation(self):
        m = b"hello"
        outs = {
            ram1024.ram_hash(m, 64)[:32],
            ram1024.ram_hash(m, 32),
            ram1024.ram_hash(m, 64, ram1024.MODE_XOF)[:32],
            ram1024.ram_hash(m, 64, ram1024.MODE_MAC, key=b"k" * 16)[:32],
            ram1024.ram_hash(m + b"\x01", 64)[:32],  # padding ambiguity check
            ram1024.ram_hash(m, 64, rounds=23, research=True)[:32],
        }
        self.assertEqual(len(outs), 6)

    def test_step_core_matches_full_core(self):
        for _ in range(5):
            m = os.urandom(64)
            self.assertEqual(lab.core(lab.RAM_STEPS, 3 * ram1024.ROUNDS, m),
                             lab.core(lab.RAM1024, ram1024.ROUNDS, m))
            self.assertEqual(lab.core(lab.RAM1024, ram1024.ROUNDS, m),
                             ram1024.ram_hash(m)[:32])

    def test_invalid_parameters_rejected(self):
        for bad in (0, 65):
            with self.assertRaises(ValueError):
                ram1024.Ram1024(rounds=bad)
        with self.assertRaises(ValueError):
            ram1024.Ram1024(mode=ram1024.MODE_HASH, key=b"k")  # key needs MAC mode
        with self.assertRaises(ValueError):
            ram1024.Ram1024(mode=ram1024.MODE_LEAF)  # internal tree modes

    def test_long_mac_keys_not_truncated(self):
        # v2 bug: the C API truncated keys to 128 bytes, so keys sharing
        # their first 128 bytes gave identical MACs.
        k1 = b"A" * 128 + b"x" * 72
        k2 = b"A" * 128 + b"y" * 72
        for impl in (lambda k: lab.ram_hash(b"msg", 64, ram1024.MODE_MAC, key=k),
                     lambda k: ram1024.ram_hash(b"msg", 64, ram1024.MODE_MAC, key=k)):
            self.assertNotEqual(impl(k1), impl(k2))
        self.assertEqual(lab.ram_hash(b"msg", 64, ram1024.MODE_MAC, key=k1),
                         ram1024.ram_hash(b"msg", 64, ram1024.MODE_MAC, key=k1))
        # key K vs K||0: same padded block, distinguished by key length
        k = b"k" * 16
        self.assertNotEqual(ram1024.ram_hash(b"m", 64, ram1024.MODE_MAC, key=k),
                            ram1024.ram_hash(b"m", 64, ram1024.MODE_MAC, key=k + b"\0"))
        # short / empty MAC keys are refused (an "unkeyed MAC" is a misuse trap)
        for short in (b"", b"k" * 15):
            with self.assertRaises(ValueError):
                ram1024.Ram1024(mode=ram1024.MODE_MAC, key=short)

    def test_c_api_rejects_bad_parameters(self):
        import numpy as np
        buf = np.zeros(64, np.uint8)
        out = lab._ptr(buf)
        f = lab._lib.ram_hash
        self.assertEqual(f(out, 64, b"x", 1, 0, 1, None, 0), -1)    # rounds 0
        self.assertEqual(f(out, 64, b"x", 1, 65, 1, None, 0), -1)   # rounds 65
        self.assertEqual(f(out, 64, b"x", 1, 64, 9, None, 0), -1)   # bad mode
        self.assertEqual(f(out, 64, b"x", 1, 64, 1, b"k", 1), -1)   # key w/o MAC
        self.assertEqual(f(out, 64, b"x", 1, 64, 3, b"k" * 15, 15), -1)  # short key
        self.assertEqual(f(out, 64, b"x", 1, 64, 3, None, 0), -1)        # no key
        self.assertEqual(f(out, 64, b"x", 1, 64, 1, None, 0), 0)

    def test_permutation_lab_matches_real_permutation(self):
        import ctypes
        self.assertEqual(lab._lib.perm_selftest(), 0)

    def test_default_output_is_1024_bits(self):
        self.assertEqual(len(ram1024.ram_hash(b"")), 128)

    def test_tree_mode_c_python_stream_parallel_agree(self):
        # The tree is flat (leaves + one root), so the slow pure-Python
        # reference only needs: one chunk, one byte over, several leaves with
        # a partial last one. Bigger inputs exercise thread/GPU splitting and
        # are checked against the single-threaded C path.
        C = ram1024.CHUNK
        for n in [C, C + 1, 3 * C + 5, 5 * C, 9 * C - 1]:
            m = os.urandom(n)
            ref = lab.ram_hash(m, 128)
            if n < 4 * C:
                self.assertEqual(ram1024.ram_hash(m), ref, n)
            self.assertEqual(_fast.hash_parallel(m), ref, n)
            self.assertEqual(_fast.hash_parallel(m, threads=3), ref, n)
            self.assertEqual(_fast.hash_parallel(m, gpu=True), ref, n)
            self.assertEqual(_fast.hash_parallel(m, gpu=True, gpu_share=1.0), ref, n)
            h = _fast.Ram1024()
            for i in range(0, n, 5000):
                h.update(m[i:i + 5000])
            self.assertEqual(h.digest(), ref, n)

    def test_tree_differs_from_plain_sponge(self):
        m = os.urandom(ram1024.CHUNK + 1)
        sp = ram1024._Sponge(128, ram1024.MODE_HASH, ram1024.ROUNDS)
        sp.update(m)
        self.assertNotEqual(sp.digest(), ram1024.ram_hash(m))

    def test_xof_prefix(self):
        long = lab.ram_hash(b"abc", 500, ram1024.MODE_XOF)
        short = lab.ram_hash(b"abc", 77, ram1024.MODE_XOF)
        self.assertEqual(long[:77], short)
        self.assertEqual(long, ram1024.ram_hash(b"abc", 500, ram1024.MODE_XOF))
        self.assertEqual(len(set(long[i:i + 128] for i in range(0, 384, 128))), 3)


class MisuseResistance(unittest.TestCase):
    """F16/F17: reduced rounds and short outputs only in research builds."""

    def test_reduced_rounds_refused(self):
        for impl in (ram1024.Ram1024, _fast.Ram1024):
            for r in (1, 8, 63):
                with self.assertRaises(ValueError):
                    impl(rounds=r)
            impl(rounds=8, research=True)  # explicit opt-in works
        with self.assertRaises(ValueError):
            _fast.hash_parallel(b"x" * 40000, rounds=8)

    def test_short_outputs_refused(self):
        for impl in (ram1024.Ram1024, _fast.Ram1024):
            with self.assertRaises(ValueError):
                impl(31)
            with self.assertRaises(ValueError):
                impl(15, ram1024.MODE_MAC, key=b"k" * 16)
            impl(32)
            impl(16, ram1024.MODE_MAC, key=b"k" * 16)
            impl(1, ram1024.MODE_XOF)  # XOF output is the caller's to size

    def test_production_c_library_refuses(self):
        if not _fast.FAST:
            self.skipTest("C library not built")
        lib = _fast._lib
        out = ctypes.create_string_buffer(64)
        self.assertEqual(lib.ram_check_params(64, ram1024.MODE_HASH, 64), 0)
        self.assertEqual(lib.ram_check_params(64, ram1024.MODE_HASH, 32), -1)
        self.assertEqual(lib.ram_check_params(16, ram1024.MODE_HASH, 64), -1)
        lib.ram_hash.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p,
                                 ctypes.c_size_t, ctypes.c_int, ctypes.c_int,
                                 ctypes.c_char_p, ctypes.c_size_t]
        self.assertEqual(lib.ram_hash(out, 64, b"", 0, 4, ram1024.MODE_HASH, None, 0), -1)

    def test_kat_file(self):
        """tests/kat.txt agrees with the C library and the reference."""
        import subprocess
        import sys
        r = subprocess.run([sys.executable, os.path.join(ROOT, "tools", "xcheck.py"), "2000"],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)


if __name__ == "__main__":
    unittest.main()
