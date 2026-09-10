"""Setuptools hook that builds native KCP only when CFFI is available.

The normal package remains installable as pure Python. A build environment
that has CFFI compiles the vendored upstream implementation; otherwise the
resulting wheel uses the Python fallback only.
"""

from setuptools import setup


try:
    import cffi  # noqa: F401
except ImportError:
    cffi_modules = []
else:
    cffi_modules = ["tuya_p2p/_kcp_build.py:ffibuilder"]

setup(cffi_modules=cffi_modules)
