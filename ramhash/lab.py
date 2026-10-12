"""ctypes bindings to the research lab library (run `make lab` first)."""

import ctypes
import os

import numpy as np

from . import _libpath

SHA256, SHA3_512, BLAKE2B, RAM1024, RAM_STEPS, BLAKE2B_HALF = range(6)
NAMES = {SHA256: "SHA-256", SHA3_512: "SHA3-512", BLAKE2B: "BLAKE2b",
         RAM1024: "RAM-1024", RAM_STEPS: "RAM-1024 (steps)",
         BLAKE2B_HALF: "BLAKE2b (half-rounds)"}

_lib = _libpath.load("ramlab")
_u8p = ctypes.POINTER(ctypes.c_uint8)
_lib.lab_core.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_char_p, _u8p]
_lib.lab_sac.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_int,
                         ctypes.POINTER(ctypes.c_uint32), ctypes.c_uint64]
_lib.lab_cube.argtypes = [ctypes.c_int] * 5 + [ctypes.c_uint64] * 2
_lib.lab_pairs.argtypes = [ctypes.c_int] * 4 + [_u8p, _u8p, ctypes.c_uint64]
_lib.lab_stream.argtypes = [ctypes.c_int, _u8p, ctypes.c_size_t, ctypes.c_uint64]
_lib.lab_bench_core.argtypes = [ctypes.c_int, ctypes.c_long]
_lib.lab_bench_core.restype = ctypes.c_double
_lib.ram_hash.argtypes = [_u8p, ctypes.c_size_t, ctypes.c_char_p,
                          ctypes.c_size_t, ctypes.c_int, ctypes.c_int,
                          ctypes.c_char_p, ctypes.c_size_t]

FULL_ROUNDS = {SHA256: 64, SHA3_512: 24, BLAKE2B: 12,
               RAM1024: _lib.lab_ram_rounds(), RAM_STEPS: 3 * _lib.lab_ram_rounds(),
               BLAKE2B_HALF: 24}


def _ptr(a):
    return a.ctypes.data_as(_u8p)


def core(alg, rounds, data64):
    out = np.zeros(32, np.uint8)
    _lib.lab_core(alg, rounds, bytes(data64), _ptr(out))
    return out.tobytes()


def ram_hash(data, outlen=64, mode=1, rounds=None, key=b""):
    out = np.zeros(outlen, np.uint8)
    _lib.ram_hash(_ptr(out), outlen, bytes(data), len(data),
                  rounds or FULL_ROUNDS[RAM1024], mode, bytes(key), len(key))
    return out.tobytes()


def sac(alg, rounds, samples, seed=1):
    counts = np.zeros(512 * 256, np.uint32)
    _lib.lab_sac(alg, rounds, samples,
                 counts.ctypes.data_as(ctypes.POINTER(ctypes.c_uint32)), seed)
    return counts.reshape(512, 256) / samples


def cube(alg, rounds, k, trials, strategy, cube_seed, trial_seed):
    return _lib.lab_cube(alg, rounds, k, trials, strategy, cube_seed, trial_seed)


def pairs(alg, rounds, delta_bit, n, seed=1):
    feats = np.zeros((n, 768), np.uint8)
    labels = np.zeros(n, np.uint8)
    _lib.lab_pairs(alg, rounds, delta_bit, n, _ptr(feats), _ptr(labels), seed)
    return feats, labels


def stream(alg, blocks, seed=1):
    out = np.zeros(blocks * 32, np.uint8)
    _lib.lab_stream(alg, _ptr(out), blocks, seed)
    return out


def bench_core(alg, iters):
    return _lib.lab_bench_core(alg, iters)


_lib.lab_rotational.argtypes = [ctypes.c_int] * 4 + [ctypes.c_uint64]
_lib.lab_rotational.restype = ctypes.c_double


def rotational(alg, rounds, n, rot=1, seed=1):
    return _lib.lab_rotational(alg, rounds, n, rot, seed)


_lib.lab_pairs_multi.argtypes = [ctypes.c_int] * 5 + [_u8p, _u8p, ctypes.c_uint64]


def pairs_multi(alg, rounds, delta_bit, k, n, seed=1):
    feats = np.zeros((n, k * 256), np.uint8)
    labels = np.zeros(n, np.uint8)
    _lib.lab_pairs_multi(alg, rounds, delta_bit, k, n, _ptr(feats), _ptr(labels), seed)
    return feats, labels
