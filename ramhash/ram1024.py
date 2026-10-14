"""RAM-1024 (v3) pure-Python reference implementation.

Readable specification of the algorithm; the C version in csrc/ram1024.c is
the fast one and must produce identical output (tests/test_ram1024.py).

    State     32 x 64-bit words as a 4x8 matrix, s[row*8 + col]
    Rate      rows 0-1   1024 bits (128-byte blocks)
    Capacity  rows 2-3   1024 bits
    Round     iota (pi constants, diagonal) -> column G -> rho (rows 2-3)
              -> diagonal G -> chi3
    Padding   pad10*1;  parameter block in s[28..31]
    Tree      hash mode, messages > 16 KiB: 16 KiB leaves -> 1024-bit CVs,
              root = sponge(CV_0 || ... || CV_n-1 || le64(n))
    Passwords RAM-Balloon (pwhash): Balloon hashing on the permutation
"""

from ._pi import pi_fraction_words

ROUNDS = 64
RATE = 128
OUTLEN = 128
CHUNK = 16384
MIN_KEY = 16
MIN_HASH_OUT = 32  # hash digests >= 256 bits
MIN_TAG = 16  # MAC tags >= 128 bits
CV = 128
VERSION_WORD = 0x52414D0300000000
RHO = (1, 27, 53, 15, 41, 3, 29, 55, 17, 43, 5, 31, 57, 19, 45, 7)
MODE_HASH, MODE_XOF, MODE_MAC, MODE_LEAF, MODE_ROOT, MODE_PW = 1, 2, 3, 4, 5, 6
MIN_SALT = 16
PW_MAX_LANES = 16
PW_MAX_T = 64
PW_MAX_KIB = 1 << 20
_PW_SLICES = 4
_M = (1 << 64) - 1
_RC = pi_fraction_words()


def _rotr(x, n):
    return ((x >> n) | (x << (64 - n))) & _M


def _g(s, a, b, c, d):
    s[a] = (s[a] + s[b]) & _M; s[d] = _rotr(s[d] ^ s[a], 32)
    s[c] = (s[c] + s[d]) & _M; s[b] = _rotr(s[b] ^ s[c], 24)
    s[a] = (s[a] + s[b]) & _M; s[d] = _rotr(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & _M; s[b] = _rotr(s[b] ^ s[c], 63)


def permute(s, rounds=ROUNDS):
    for r in range(rounds):
        for c in range(8):
            s[(c & 3) * 8 + c] ^= _RC[r * 8 + c]
        for c in range(8):
            _g(s, c, 8 + c, 16 + c, 24 + c)
        for i, k in enumerate(RHO):
            s[16 + i] = _rotr(s[16 + i], 64 - k)
        for c in range(8):
            _g(s, c, 8 + (c + 1) % 8, 16 + (c + 2) % 8, 24 + (c + 3) % 8)
        r0, r1, r2 = [i for i in range(4) if i != r % 4]
        for c in range(8):
            x, y, z = r0 * 8 + c, r1 * 8 + (c + 3) % 8, r2 * 8 + (c + 5) % 8
            X, Y, Z = s[x], s[y], s[z]
            s[x] = X ^ (~Y & Z & _M)
            s[y] = Y ^ (~Z & X & _M)
            s[z] = Z ^ (~X & Y & _M)


def _absorb(s, block, rounds):
    for i in range(16):
        s[i] ^= int.from_bytes(block[8 * i:8 * i + 8], "little")
    permute(s, rounds)


class _Sponge:
    def __init__(self, outlen, mode, rounds, keylen=0, node=0):
        self.s = s = [0] * 32
        self.rounds, self.outlen = rounds, outlen
        self.buf = b""
        s[31] = VERSION_WORD | (mode << 24) | (rounds << 16)
        s[30] = 0 if mode == MODE_XOF else outlen
        s[29] = keylen
        s[28] = node

    def update(self, data):
        buf = self.buf + bytes(data)
        full = len(buf) - len(buf) % RATE
        for i in range(0, full, RATE):
            _absorb(self.s, buf[i:i + RATE], self.rounds)
        self.buf = buf[full:]

    def digest(self):
        s = list(self.s)
        last = bytearray(self.buf.ljust(RATE, b"\0"))
        last[len(self.buf)] ^= 0x01
        last[RATE - 1] ^= 0x80
        _absorb(s, last, self.rounds)
        out = bytearray()
        while True:
            out += b"".join(w.to_bytes(8, "little") for w in s[:16])
            if len(out) >= self.outlen:
                return bytes(out[:self.outlen])
            permute(s, self.rounds)


def _leaf(chunk, index, rounds):
    sp = _Sponge(CV, MODE_LEAF, rounds, node=index)
    sp.update(chunk)
    return sp.digest()


def check_params(outlen, mode, rounds, key=b"", research=False):
    """Raise ValueError unless the parameters are accepted (no hashing)."""
    # Misuse resistance: reduced rounds and short outputs only for
    # cryptanalysis, never by accident.
    if research:
        if not 1 <= rounds <= len(_RC) // 8:
            raise ValueError("rounds must be 1..%d" % (len(_RC) // 8))
    elif rounds != ROUNDS:
        raise ValueError("rounds must be %d (reduced rounds need research=True)"
                         % ROUNDS)
    elif outlen < {MODE_HASH: MIN_HASH_OUT, MODE_MAC: MIN_TAG}.get(mode, 1):
        raise ValueError("output too short for mode %d" % mode)
    if mode not in (MODE_HASH, MODE_XOF, MODE_MAC):
        raise ValueError("bad mode")
    if key and mode != MODE_MAC:
        raise ValueError("key only allowed in MAC mode")
    if mode == MODE_MAC and len(key) < MIN_KEY:
        raise ValueError("MAC key must be at least %d bytes" % MIN_KEY)
    if outlen <= 0:
        raise ValueError("outlen must be positive")


class Ram1024:
    """Streaming RAM-1024 (hashlib-style update/digest)."""

    def __init__(self, outlen=OUTLEN, mode=MODE_HASH, rounds=ROUNDS, key=b"",
                 research=False):
        check_params(outlen, mode, rounds, key, research)
        self._mode, self._rounds, self._outlen = mode, rounds, outlen
        self._data = bytearray()  # reference keeps the message (O(n) memory)
        self._sp = _Sponge(outlen, mode, rounds, len(key))
        if key:  # any length; zero-padded to whole blocks, length in s[29]
            pad = -len(key) % RATE
            self._sp.update(bytes(key) + b"\0" * pad)

    def update(self, data):
        if self._mode == MODE_HASH:
            self._data += data  # bytearray: amortised O(1) append
        else:
            self._sp.update(data)

    def digest(self):
        if self._mode != MODE_HASH or len(self._data) <= CHUNK:
            if self._mode == MODE_HASH:
                sp = _Sponge(self._outlen, MODE_HASH, self._rounds)
                sp.update(bytes(self._data))
                return sp.digest()
            return self._sp.digest()
        d = bytes(self._data)
        n = (len(d) + CHUNK - 1) // CHUNK
        root = _Sponge(self._outlen, MODE_ROOT, self._rounds)
        for i in range(n):
            root.update(_leaf(d[i * CHUNK:(i + 1) * CHUNK], i, self._rounds))
        root.update(n.to_bytes(8, "little"))
        return root.digest()

    def hexdigest(self):
        return self.digest().hex()


def ram_hash(data, outlen=OUTLEN, mode=MODE_HASH, rounds=ROUNDS, key=b"",
             research=False):
    h = Ram1024(outlen, mode, rounds, key, research)
    h.update(data)
    return h.digest()


# --- RAM-Balloon password hashing (spec: SPEC.md; fast version in C) ---

_PW_DELTA = 3
_PW_SALT, _PW_FINAL = _M - 1, _M - 2


def _pw_compress(kind, lane, ctr, x, y):
    """One permutation: rate = x || y (8 + 8 words), capacity = parameter
    block with mode PW, kind, lane, counter; output = first 8 words."""
    s = list(x) + list(y) + [0] * 16
    s[31] = VERSION_WORD | (MODE_PW << 24) | (ROUNDS << 16) | (kind << 8)
    s[30], s[29], s[28] = 64, lane, ctr
    permute(s)
    return s[:8]


def _le64(v):
    return v.to_bytes(8, "little")


def _words(b):
    return [int.from_bytes(b[8 * i:8 * i + 8], "little") for i in range(8)]


def pwhash(password, salt, outlen=64, m_kib=16384, t_cost=3, lanes=4):
    """RAM-Balloon v2. Reference only: far too slow for real parameters.

    Lanes run slice by slice (4 slices per pass); within a slice, lane l
    reads other lanes only outside that slice, so running the lanes one
    after another here gives the same result as the parallel C code."""
    if (outlen < MIN_HASH_OUT or len(salt) < MIN_SALT or not 1 <= t_cost <= PW_MAX_T
            or not 1 <= lanes <= PW_MAX_LANES or not 8 * lanes <= m_kib <= PW_MAX_KIB):
        raise ValueError("bad RAM-Balloon parameters")
    n = (m_kib * 16 // lanes) & ~(_PW_SLICES - 1)
    seg = n // _PW_SLICES
    sd = _Sponge(64, MODE_PW, ROUNDS, node=_PW_SALT)
    sd.update(_le64(len(salt)) + salt)
    sd = _words(sd.digest())
    zero = [0] * 8
    B, ctr = [], []
    for lane in range(lanes):                                   # expand
        sp = _Sponge(64, MODE_PW, ROUNDS, node=lane)
        sp.update(_le64(len(password)) + password + _le64(len(salt)) + salt
                  + _le64(m_kib) + _le64(t_cost) + _le64(lanes) + _le64(outlen))
        L = [_pw_compress(1, lane, 0, _words(sp.digest()), zero)]
        for m in range(1, n):
            L.append(_pw_compress(1, lane, m, L[m - 1], zero))
        B.append(L)
        ctr.append(n)
    for t in range(t_cost):                                     # mix
        for sl in range(_PW_SLICES):
            for lane in range(lanes):
                L, c = B[lane], ctr[lane]
                for m in range(sl * seg, (sl + 1) * seg):
                    L[m] = _pw_compress(2, lane, c, L[(m - 1) % n], L[m])
                    c += 1
                    r = _pw_compress(3, lane, 0, sd, [t, m] + [0] * 6)
                    for i in range(_PW_DELTA):
                        if i == 0 and lanes > 1:
                            l2 = (lane + 1 + r[3] % (lanes - 1)) % lanes
                            k = r[0] % (n - seg)
                            if k >= sl * seg:
                                k += seg
                            nb = B[l2][k]
                        else:
                            nb = L[r[i] % n]
                        L[m] = _pw_compress(2, lane, c, L[m], nb)
                        c += 1
                ctr[lane] = c
    final = _Sponge(outlen, MODE_PW, ROUNDS, node=_PW_FINAL)
    for lane in range(lanes):
        final.update(b"".join(_le64(w) for w in B[lane][n - 1]))
    final.update(_le64(lanes))
    return final.digest()
