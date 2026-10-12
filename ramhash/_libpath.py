"""Locate the compiled C libraries on any OS (.dylib / .so / .dll)."""

import ctypes
import glob
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_SRC = os.path.join(_HERE, "..")
# ../build only in a source checkout (next to the Makefile), never as a
# generic site-packages/build directory that another package could fill.
_DIRS = (_HERE,) + ((os.path.join(_SRC, "build"),)
                    if os.path.exists(os.path.join(_SRC, "Makefile")) else ())
_EXTS = {"darwin": ("dylib", "so"), "win32": ("dll",), "cygwin": ("dll",)}


def find(name):
    """Path of the compiled library: $RAMHASH_<NAME>, the pip-built
    ramhash/_libram.*, or lib<name>.* next to the package or in ../build."""
    env = os.environ.get("RAMHASH_" + name.upper())
    if env:  # absolute paths only: a bare name would go through the loader search path
        return env if os.path.isabs(env) else None
    if name == "ram":  # built by `pip install` (setup.py) next to the package
        for p in sorted(glob.glob(os.path.join(_HERE, "_libram*"))):
            if p.endswith((".so", ".pyd", ".dylib", ".dll")):
                return p
    for d in _DIRS:
        for ext in _EXTS.get(sys.platform, ("so",)):
            p = os.path.join(d, "lib%s.%s" % (name, ext))
            if os.path.exists(p):
                return os.path.abspath(p)
    return None


def load(name):
    """ctypes handle for lib<name>; raises OSError if it is not built."""
    p = find(name)
    if p is None:
        raise OSError("lib%s not built (run `make`)" % name)
    return ctypes.CDLL(p)
