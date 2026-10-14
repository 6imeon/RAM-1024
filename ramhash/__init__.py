"""ramhash: a hardened, crypto-agile replacement for bare SHA-256.

Design rules:
  * RAM-1024 (ramhash/ram1024.py, csrc/ram1024.c) is a new 2048-bit sponge
    hash with a 1024-bit capacity and 1024-bit output. Because any new
    design is untrusted until it has survived years of public
    cryptanalysis, the default "ram-1024+sha3-512" concatenates it with
    NIST SHA3-512: the result is
    at least as strong as the stronger of the two.
  * Long outputs: the default is a 1536-bit concatenation (1024-bit
    RAM-1024 || 512-bit SHA3-512), and every non-legacy algorithm gives at
    least 512 bits: >= 256-bit collision security, and preimage security
    that stays >= 2^128 even against Grover-style quantum search (SHA-256
    drops to 2^128 preimage / ~2^85 collision).
  * Self-describing, versioned encodings ("$rh1$<alg>$<hex>") so the
    algorithm can be swapped later without breaking stored digests.
  * A dual-hash combiner (SHA3-512 || BLAKE2b-512) that stays
    collision-resistant as long as EITHER underlying design holds.
  * Constant-time verification and memory-hard password hashing
    (RAM-Balloon; PBKDF2 only as a fallback).
"""

import hashlib
import hmac
import os
import re

from . import _fast
from ._fast import Ram1024, hash_parallel

__all__ = [
    "DEFAULT_ALG", "ALGORITHMS",
    "digest", "digest_file", "verify", "needs_rehash",
    "keyed_digest", "verify_keyed",
    "hash_password", "verify_password", "needs_rehash_password",
]

VERSION = "rh1"
DEFAULT_ALG = "ram-1024+sha3-512"
_CHUNK = 1 << 20


def _blake2b():
    return hashlib.blake2b(digest_size=64)


# Constructors for streaming hashers. Legacy algorithms are accepted for
# verification/migration only and are flagged by needs_rehash().
_SINGLE = {
    "ram-1024": Ram1024,
    "sha3-512": hashlib.sha3_512,
    "blake2b-512": _blake2b,
    "sha512": hashlib.sha512,
    "sha256": hashlib.sha256,  # legacy
}
ALGORITHMS = tuple(_SINGLE) + (DEFAULT_ALG, "sha3-512+blake2b-512")
_LEGACY = {"sha256"}


class _Hasher:
    """Streaming hasher for a single algorithm or a '+'-joined combination."""

    def __init__(self, alg):
        if alg not in ALGORITHMS:
            raise ValueError("unknown algorithm: %r" % alg)
        self._parts = [_SINGLE[a]() for a in alg.split("+")]

    def update(self, data):
        for h in self._parts:
            h.update(data)

    def hexdigest(self):
        # Concatenation combiner: a collision for the whole output requires
        # a simultaneous collision in every component.
        return "".join(h.hexdigest() for h in self._parts)


def _encode(alg, hexdigest):
    return "$%s$%s$%s" % (VERSION, alg, hexdigest)


def _decode(encoded):
    parts = encoded.split("$")
    if len(parts) != 4 or parts[0] or parts[1] != VERSION:
        raise ValueError("not a ramhash digest")
    return parts[2], parts[3]


def _as_bytes(data):
    if isinstance(data, str):
        return data.encode("utf-8")
    if isinstance(data, (bytes, bytearray, memoryview)):
        return bytes(data)
    raise TypeError("expected str or bytes-like, got %s" % type(data).__name__)


def digest(data, alg=DEFAULT_ALG):
    """Return the encoded digest of bytes/str ``data``."""
    h = _Hasher(alg)
    h.update(_as_bytes(data))
    return _encode(alg, h.hexdigest())


def digest_file(path, alg=DEFAULT_ALG):
    """Return the encoded digest of a file, streamed in 1 MiB chunks."""
    h = _Hasher(alg)
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(_CHUNK), b""):
            h.update(chunk)
    return _encode(alg, h.hexdigest())


def verify(data, encoded, allow_legacy=False):
    """Constant-time check that ``data`` matches ``encoded``.

    Legacy SHA-256 digests (bare 64-char hex or "$rh1$sha256$...") are
    rejected unless ``allow_legacy=True``: otherwise whoever supplies the
    digest could downgrade verification to the weaker algorithm. A malformed
    or non-string ``encoded`` returns False instead of raising; ``data``
    must be str or bytes-like (TypeError otherwise), as for digest().
    """
    data = _as_bytes(data)  # caller error: raise whatever ``encoded`` is
    if not isinstance(encoded, str) or not encoded.isascii():
        return False
    if "$" not in encoded and len(encoded) == 64:
        encoded = _encode("sha256", encoded.lower())
    try:
        alg, _ = _decode(encoded)
        if alg in _LEGACY and not allow_legacy:
            return False
        return hmac.compare_digest(digest(data, alg), encoded)
    except ValueError:
        return False


def needs_rehash(encoded, alg=DEFAULT_ALG):
    """True if ``encoded`` should be recomputed with the current algorithm
    (also for malformed or non-string input; never raises)."""
    if not isinstance(encoded, str) or "$" not in encoded:
        return True
    try:
        stored_alg, _ = _decode(encoded)
    except ValueError:
        return True
    return stored_alg != alg


# --- Keyed hashing (MACs): use these instead of sha256(secret + data) ---

def keyed_digest(key, data):
    """HMAC-SHA3-512. Immune to the length-extension flaw of bare SHA-256."""
    tag = hmac.new(_as_bytes(key), _as_bytes(data), hashlib.sha3_512).hexdigest()
    return _encode("hmac-sha3-512", tag)


def verify_keyed(key, data, encoded):
    try:
        return hmac.compare_digest(keyed_digest(key, data), encoded)
    except (ValueError, TypeError, OverflowError, MemoryError):  # never raise
        return False


# --- Password hashing: fast hashes like SHA-256 are WRONG for passwords ---
#
# Default: RAM-Balloon, a memory-hard function (Balloon hashing on the
# RAM-1024 permutation, data-independent memory access). Each guess costs
# an attacker the memory as well as the time, which is what GPU and ASIC
# cracking rigs lack. PBKDF2 stays for hosts without the C library and for
# verifying old hashes.

PW_MEMORY_KIB = 16384  # 16 MiB, all held at once (lanes reference each other)
PW_TIME_COST = 3       # passes; >= 3 against depth-reduction attacks on iMHFs
PW_LANES = 4
PW_OUTLEN = 64
PW_ALG = "ram-balloon2"
# Ceilings, enforced when hashing and when reading stored hashes back (DoS:
# whoever can write a stored hash must not make verification arbitrarily
# slow, and hash_password must never produce a hash verify would refuse).
PW_MAX_TIME_COST = 64
PW_MAX_LANES = 16
PW_MAX_MEMORY_KIB = 4 * PW_MEMORY_KIB  # stored hashes: at most 4x the default memory
PBKDF2_ITERATIONS = 210_000  # OWASP 2023 recommendation for PBKDF2-HMAC-SHA512
PBKDF2_MAX_ITERATIONS = 4 * PBKDF2_ITERATIONS
PBKDF2_DKLEN = 64
_PW_THREADS = 4  # verification cost is bounded assuming at most this many cores help
PW_MAX_COST = 8 * (PW_MEMORY_KIB * (4 * PW_TIME_COST + 1) // PW_LANES)  # 8x default work
_BALLOON_RE = re.compile(r"m=([1-9][0-9]{0,9}),t=([1-9][0-9]{0,2}),p=([1-9][0-9]?)")
_HEX_RE = re.compile(r"(?:[0-9a-f]{2}){16,1024}")


def _check_balloon(m, t, p):
    if not all(type(v) is int for v in (m, t, p)):
        raise TypeError("RAM-Balloon parameters must be int")
    if not (1 <= t <= PW_MAX_TIME_COST and 1 <= p <= PW_MAX_LANES
            and 8 * p <= m <= PW_MAX_MEMORY_KIB and _pw_cost(m, t, p) <= PW_MAX_COST):
        raise ValueError("RAM-Balloon parameters out of range")
    return m, t, p


def _pw_cost(m, t, p):
    """Wall-clock work: expansion (1 call per block) + t passes (4 calls per
    block), spread over at most _PW_THREADS lanes."""
    return m * (4 * t + 1) // min(p, _PW_THREADS)


def hash_password(password, memory_kib=PW_MEMORY_KIB, time_cost=PW_TIME_COST,
                  lanes=PW_LANES):
    """Salted, memory-hard password hash: "$rh1$ram-balloon2$m=..,t=..,p=..$salt$hash".

    Falls back to PBKDF2-HMAC-SHA512 if the C library is not built (the
    pure-Python RAM-Balloon is far too slow for real parameters)."""
    _check_balloon(memory_kib, time_cost, lanes)
    salt = os.urandom(32)
    if not _fast.FAST:
        return _hash_password_pbkdf2(password, salt)
    dk = _fast.pwhash(_as_bytes(password), salt, PW_OUTLEN, memory_kib, time_cost, lanes)
    return "$%s$%s$m=%d,t=%d,p=%d$%s$%s" % (
        VERSION, PW_ALG, memory_kib, time_cost, lanes, salt.hex(), dk.hex())


def _hash_password_pbkdf2(password, salt, iterations=PBKDF2_ITERATIONS):
    dk = hashlib.pbkdf2_hmac("sha512", _as_bytes(password), salt, iterations)
    return "$%s$pbkdf2-sha512$%d$%s$%s" % (VERSION, iterations, salt.hex(), dk.hex())


def _parse_balloon(params):
    """Strict: one canonical spelling per parameter set (no '+', '_',
    spaces, leading zeros or repeated keys), so stored strings compare."""
    mt = _BALLOON_RE.fullmatch(params)
    if not mt:
        raise ValueError("bad parameters")
    return _check_balloon(*(int(g) for g in mt.groups()))


def verify_password(password, encoded):
    """Constant-time check of a password against hash_password() output.
    Returns False (never raises) on malformed or out-of-range input."""
    try:
        head, ver, alg, params, salt_hex, dk_hex = encoded.split("$")
        if head or ver != VERSION or not (_HEX_RE.fullmatch(salt_hex) and _HEX_RE.fullmatch(dk_hex)):
            return False
        salt, want = bytes.fromhex(salt_hex), bytes.fromhex(dk_hex)
        if alg == PW_ALG:
            m, t, p = _parse_balloon(params)
            if len(want) != PW_OUTLEN or not _fast.FAST:
                return False  # the pure-Python reference would take hours
            dk = _fast.pwhash(_as_bytes(password), salt, PW_OUTLEN, m, t, p)
        elif alg == "pbkdf2-sha512":
            if not re.fullmatch(r"[1-9][0-9]{0,8}", params) or len(want) != PBKDF2_DKLEN:
                return False
            n = int(params)
            if n > PBKDF2_MAX_ITERATIONS:
                return False
            dk = hashlib.pbkdf2_hmac("sha512", _as_bytes(password), salt, n, PBKDF2_DKLEN)
        else:
            return False
    except (ValueError, AttributeError, TypeError, OverflowError, MemoryError):
        return False
    return hmac.compare_digest(dk, want)


def needs_rehash_password(encoded, memory_kib=PW_MEMORY_KIB, time_cost=PW_TIME_COST,
                          lanes=PW_LANES):
    """True if ``encoded`` is PBKDF2, an older RAM-Balloon version, or
    weaker than the requested parameters (memory, passes or lanes)."""
    try:
        head, ver, alg, params, salt_hex, dk_hex = encoded.split("$")
        if head or ver != VERSION or not (_HEX_RE.fullmatch(salt_hex)
                                          and _HEX_RE.fullmatch(dk_hex)):
            return True  # corrupt: verify_password could never accept it
        if alg == "pbkdf2-sha512":
            if int(params) < PBKDF2_ITERATIONS or len(dk_hex) != 2 * PBKDF2_DKLEN:
                return True
            return _fast.FAST  # upgrade once the memory-hard function is available
        if alg != PW_ALG:
            return True
        m, t, p = _parse_balloon(params)
        return m < memory_kib or t < time_cost or p != lanes
    except (ValueError, AttributeError, TypeError):
        return True
