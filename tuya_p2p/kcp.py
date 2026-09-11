"""Backend-neutral KCP transport API.

``auto`` is deliberately resolved when an instance is created: a wheel may
gain a native extension after this module was imported.  A deliberate
library-wide default is also available for integration tests and deployments.
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator, Literal

from ._kcp_common import *  # re-export the established KCP constants/config
from ._kcp_common import KCPConfig, OutputCallback

KCPBackend = Literal["auto", "native", "python"]
_default_backend: KCPBackend = "auto"


def _validate_backend(backend: str) -> KCPBackend:
    if backend not in ("auto", "native", "python"):
        raise ValueError("backend must be 'auto', 'native', or 'python'")
    return backend  # type: ignore[return-value]


def get_default_backend() -> KCPBackend:
    """Return the process-wide choice for KCP instances without a backend."""
    return _default_backend


def set_default_backend(backend: KCPBackend) -> KCPBackend:
    """Set the process-wide backend for subsequently created implicit KCPs.

    Returns the previous choice, making a caller-managed restoration simple.
    Passing ``"auto"`` restores the normal preferred-native behavior.
    Explicit ``KCP(..., backend=...)`` selections always take precedence.
    """
    global _default_backend
    previous = _default_backend
    _default_backend = _validate_backend(backend)
    return previous


@contextmanager
def using_backend(backend: KCPBackend) -> Iterator[None]:
    """Temporarily set the process-wide default and always restore it."""
    previous = set_default_backend(backend)
    try:
        yield
    finally:
        set_default_backend(previous)


def native_available() -> bool:
    """Return whether the optional CFFI implementation can be imported."""
    try:
        from . import _kcp_native_backend  # noqa: F401
    except ImportError:
        return False
    return True


def available_backends() -> tuple[Literal["python", "native"], ...]:
    """Return installed concrete backends, in preference order."""
    return ("native", "python") if native_available() else ("python",)


def _implementation(backend: KCPBackend):
    backend = _validate_backend(backend)
    if backend == "python":
        from ._kcp_python import PythonKCP

        return PythonKCP
    if backend == "native":
        try:
            from ._kcp_native_backend import NativeKCP
        except ImportError as exc:
            raise RuntimeError(
                "the native KCP backend is unavailable; install nexxt-lan[native] "
                "with a supported native build"
            ) from exc
        return NativeKCP
    if backend == "auto":
        if native_available():
            from ._kcp_native_backend import NativeKCP

            return NativeKCP
        from ._kcp_python import PythonKCP

        return PythonKCP
    raise AssertionError("validated backend was not handled")


class KCP:
    """Create a KCP transport using the selected implementation.

    The returned object implements the stable KCP transport contract.  Callers
    normally omit ``backend``. Such instances use the library-wide default,
    initially ``auto``; explicit selection takes precedence over that default.
    """

    def __new__(
        cls,
        conv: int,
        output: OutputCallback,
        config: KCPConfig | None = None,
        *,
        backend: KCPBackend | None = None,
    ):
        return _implementation(_default_backend if backend is None else backend)(
            conv, output, config
        )


__all__ = [
    "KCP",
    "KCPBackend",
    "KCPConfig",
    "available_backends",
    "get_default_backend",
    "native_available",
    "set_default_backend",
    "using_backend",
    "UPSTREAM_REPOSITORY",
    "UPSTREAM_COMMIT",
    "IKCP_RTO_NDL",
    "IKCP_RTO_MIN",
    "IKCP_RTO_DEF",
    "IKCP_RTO_MAX",
    "IKCP_CMD_PUSH",
    "IKCP_CMD_ACK",
    "IKCP_CMD_WASK",
    "IKCP_CMD_WINS",
    "IKCP_ASK_SEND",
    "IKCP_ASK_TELL",
    "IKCP_WND_SND",
    "IKCP_WND_RCV",
    "IKCP_MTU_DEF",
    "IKCP_ACK_FAST",
    "IKCP_INTERVAL",
    "IKCP_OVERHEAD",
    "IKCP_DEADLINK",
    "IKCP_THRESH_INIT",
    "IKCP_THRESH_MIN",
    "UINT32_MASK",
]
