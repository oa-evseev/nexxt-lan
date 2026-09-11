"""Setuptools metadata derived from the repository's single VERSION file."""

from pathlib import Path

from setuptools import find_packages, setup


VERSION = (Path(__file__).parent / "VERSION").read_text(encoding="utf-8").strip()

setup(
    name="nexxt-lan",
    version=VERSION,
    description="Local LAN client for supported Nexxt/Tuya camera RTC paths",
    long_description=(Path(__file__).parent / "README.md").read_text(encoding="utf-8"),
    long_description_content_type="text/markdown",
    license="MIT",
    python_requires=">=3.10",
    install_requires=["cryptography>=41"],
    extras_require={
        "discovery": ["tinytuya>=1.20"],
        "native": [f"nexxt-lan-native=={VERSION}"],
        "test": ["pytest>=8"],
        "dev": ["pytest>=8", "black>=24", "build>=1.2", "twine>=5"],
    },
    py_modules=["nexxt_lan"],
    packages=find_packages(include=["nexxt*", "tuya_p2p*"]),
    package_data={"tuya_p2p": ["vendor/kcp/LICENSE", "vendor/kcp/REVISION"]},
    entry_points={"console_scripts": ["nexxt-lan=nexxt_lan:main"]},
)
