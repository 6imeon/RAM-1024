"""Streaming RAM-1024 backed by the C library; falls back to pure Python."""

import ctypes
import os
import warnings

from . import _libpath, ram1024

# RAM-Balloon v2 KAT (tests/kat_pwhash.txt: outlen 40, m 16, t 2, p 2, pw 3
# bytes, salt 33 bytes). Checked at load so that a stale library (e.g. an
# old pip build with the v1 algorithm, same ABI) is never used silently.
_PW_KAT = ("6716e341bce15d0585a4e8d3eacfd79159f855dcf4594ef40f1be2d61d6831c4"
           "60dabb38ebde0809")


def _kat_bytes(n, key=False):
    return bytes(((i * 31 + 0xA5) if key else (i * i * 7 + i * 13 + 1)) & 0xFF
                 for i in range(n))


def _selftest(lib):
    out = ctypes.create_string_buffer(40)
    pw, salt = _kat_bytes(3), _kat_bytes(33, key=True)
    return (lib.ram_pwhash(out, 40, pw, 3, salt, 33, 16, 2, 2) == 0
            and out.raw.hex() == _PW_KAT)


def _bind(lib):
    lib.ram_init.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int,
                             ctypes.c_int, ctypes.c_char_p, ctypes.c_size_t]
    lib.ram_update.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t]
    lib.ram_final.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    lib.ram_ctx_size.restype = ctypes.c_size_t
    lib.ram_hash_tree.argtypes = [ctypes.c_char_p, ctypes.c_size_t,
                                  ctypes.c_char_p, ctypes.c_size_t,
                                  ctypes.c_int, ctypes.c_int]
    lib.ram_pwhash.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p,
                               ctypes.c_size_t, ctypes.c_char_p, ctypes.c_size_t,
                               ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32]
    if hasattr(lib, "ram_hash_gpu"):
        lib.ram_hash_gpu.argtypes = [ctypes.c_char_p, ctypes.c_size_t,
                                     ctypes.c_char_p, ctypes.c_size_t,
                                     ctypes.c_int, ctypes.c_double]
    return lib


try:
    _lib = _bind(_libpath.load("ram"))
    _CTX_BYTES = _lib.ram_ctx_size()
    if not _selftest(_lib):
        warnings.warn("ramhash: C library %s fails its known-answer test (stale or "
                      "mismatched build); using the pure-Python fallback"
                      % _libpath.find("ram"), RuntimeWarning)
        _lib = None
except (OSError, AttributeError) as e:
    if os.environ.get("RAMHASH_RAM"):
        warnings.warn("ramhash: RAMHASH_RAM is set but unusable (%s; absolute path "
                      "required); using the pure-Python fallback" % e, RuntimeWarning)
    _lib = None

_research = None


def _lib_for(research):
    """The production library, or (research=True) the lab build, which
    also accepts reduced-round instances."""
    global _research
    if not research:
        return _lib
    if _research is None:
        _research = _bind(_libpath.load("ramlab"))
    return _research


class _CRam1024:
    def __init__(self, outlen=ram1024.OUTLEN, mode=ram1024.MODE_HASH,
                 rounds=ram1024.ROUNDS, key=b"", research=False):
        ram1024.Ram1024(outlen, mode, rounds, key, research)  # validate
        self._lib = _lib_for(research)
        self._ctx = ctypes.create_string_buffer(_CTX_BYTES)
        self._outlen = outlen
        if self._lib.ram_init(self._ctx, outlen, mode, rounds, bytes(key), len(key)):
            raise ValueError("bad parameters")

    def update(self, data):
        data = bytes(data)
        if self._lib.ram_update(self._ctx, data, len(data)):
            raise ValueError("context not initialised")

    def digest(self):
        ctx = ctypes.create_string_buffer(self._ctx.raw, _CTX_BYTES)  # copy: digest() repeatable
        out = ctypes.create_string_buffer(self._outlen)
        self._lib.ram_final(ctx, out)
        return out.raw

    def hexdigest(self):
        return self.digest().hex()


def hash_parallel(data, outlen=ram1024.OUTLEN, rounds=ram1024.ROUNDS, threads=0,
                  gpu=False, gpu_share=-1.0, research=False):
    """One-shot hash mode using all cores, and optionally the GPU (macOS
    Metal). Same digest as Ram1024 either way."""
    ram1024.Ram1024(outlen, ram1024.MODE_HASH, rounds, b"", research)  # validate
    gpu_share = float(gpu_share)
    if not (gpu_share < 0 or 0 <= gpu_share <= 1):  # also rejects NaN
        raise ValueError("gpu_share must be in [0, 1] (or negative for auto)")
    if not _lib:
        return ram1024.ram_hash(data, outlen, rounds=rounds, research=research)
    lib = _lib_for(research)
    out = ctypes.create_string_buffer(outlen)
    data = bytes(data)
    if gpu and threads == 0 and hasattr(lib, "ram_hash_gpu"):
        rc = lib.ram_hash_gpu(out, outlen, data, len(data), rounds, gpu_share)
    else:
        rc = lib.ram_hash_tree(out, outlen, data, len(data), rounds, threads)
    if rc:
        raise ValueError("bad parameters")
    return out.raw


def pwhash(password, salt, outlen=64, m_kib=16384, t_cost=3, lanes=4):
    """RAM-Balloon memory-hard password hash (C; the pure-Python reference
    is only practical for tiny test parameters)."""
    password, salt = bytes(password), bytes(salt)
    for v in (outlen, m_kib, t_cost, lanes):  # ctypes would wrap silently
        if type(v) is not int or not 0 < v < 1 << 32:
            raise ValueError("RAM-Balloon parameters must be positive 32-bit ints")
    if not _lib:
        return ram1024.pwhash(password, salt, outlen, m_kib, t_cost, lanes)
    out = ctypes.create_string_buffer(outlen)
    rc = _lib.ram_pwhash(out, outlen, password, len(password), salt, len(salt),
                         m_kib, t_cost, lanes)
    if rc == -2:
        raise MemoryError("RAM-Balloon: cannot allocate %d KiB" % m_kib)
    if rc:
        raise ValueError("bad RAM-Balloon parameters")
    return out.raw


Ram1024 = _CRam1024 if _lib else ram1024.Ram1024
FAST = _lib is not None
