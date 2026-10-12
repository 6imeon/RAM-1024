"""Builds the C library as ramhash/_libram.* (loaded with ctypes) on any OS
with a C compiler. If compilation fails the package still installs and runs
on the pure-Python reference (slow, same digests)."""

import os
import sys

from setuptools import Extension, setup
from setuptools.command.build_ext import build_ext


class OptionalBuildExt(build_ext):
    def run(self):
        try:
            super().run()
        except Exception as e:  # no compiler: pure-Python fallback
            print("warning: C library not built (%s); using pure Python" % e)

    def build_extension(self, ext):
        try:
            super().build_extension(ext)
        except Exception as e:
            print("warning: C library not built (%s); using pure Python" % e)

    def get_export_symbols(self, ext):
        return []  # plain C library for ctypes, not a Python module

    def build_extensions(self):
        msvc = self.compiler.compiler_type == "msvc"
        for ext in self.extensions:
            ext.extra_compile_args = ["/O2"] if msvc else ["-O3", "-std=c99"]
        super().build_extensions()


windows = sys.platform == "win32"
setup(ext_modules=[Extension(
    "ramhash._libram",
    sources=[os.path.join("csrc", "ram1024.c")],
    include_dirs=["csrc"],
    define_macros=[("RAM_BUILD_DLL", None)] if windows else [],
    libraries=[] if windows else ["pthread"],
    optional=True,
)], cmdclass={"build_ext": OptionalBuildExt})
