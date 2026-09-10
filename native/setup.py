"""Build the standalone optional native KCP extension."""

from pathlib import Path
from shutil import copyfile

from setuptools import setup
from setuptools.command.sdist import sdist as _sdist


PACKAGE_DIR = Path(__file__).parent


def _version_file() -> Path:
    """Use the canonical file in a checkout or the copy in an sdist."""
    for candidate in (PACKAGE_DIR / "VERSION", PACKAGE_DIR.parent / "VERSION"):
        if candidate.is_file():
            return candidate
    raise RuntimeError("VERSION is missing from the native source distribution")


VERSION = _version_file().read_text(encoding="utf-8").strip()


class sdist(_sdist):
    """Put the canonical version into an independently buildable sdist."""

    def make_release_tree(self, base_dir, files):
        super().make_release_tree(base_dir, files)
        copyfile(_version_file(), Path(base_dir) / "VERSION")


setup(
    name="nexxt-lan-native",
    version=VERSION,
    description="Optional native KCP extension for nexxt-lan",
    long_description=(PACKAGE_DIR / "README.md").read_text(encoding="utf-8"),
    long_description_content_type="text/markdown",
    license="MIT",
    license_files=["vendor/kcp/LICENSE"],
    python_requires=">=3.10",
    install_requires=["cffi>=1.15"],
    cffi_modules=["_kcp_build.py:ffibuilder"],
    cmdclass={"sdist": sdist},
)
