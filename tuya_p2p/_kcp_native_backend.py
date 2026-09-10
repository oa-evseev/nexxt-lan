"""Optional CFFI backend for the official vendored KCP C implementation."""

from __future__ import annotations

import operator
import sys
import weakref
from collections.abc import Callable, Iterator
from types import TracebackType
from typing import Any

from ._kcp_common import (
    IKCP_INTERVAL,
    IKCP_MTU_DEF,
    IKCP_WND_RCV,
    IKCP_WND_SND,
    KCPConfig,
    UINT32_MASK,
)

try:
    from _nexxt_lan_kcp_native import ffi, lib
except ModuleNotFoundError as exc:  # pragma: no cover - packaging failure only
    raise ImportError(
        "the native KCP extension is not built; install the project before use"
    ) from exc


def _u32(value: int) -> int:
    return operator.index(value) & UINT32_MASK


class _QueueView:
    """Read-only compatibility view for native KCP queue diagnostics."""

    __slots__ = ("_owner_ref", "_size_field", "_name")

    def __init__(self, owner: NativeKCP, size_field: str, name: str) -> None:
        self._owner_ref = weakref.ref(owner)
        self._size_field = size_field
        self._name = name

    def __len__(self) -> int:
        owner = self._owner_ref()
        if owner is None:
            return 0
        owner._ensure_open()
        return int(getattr(owner._native, self._size_field))

    def __iter__(self) -> Iterator[Any]:
        raise TypeError(
            f"{self._name} is an opaque native queue; only len() is supported"
        )

    def __repr__(self) -> str:
        return f"<{self._name} native queue, length={len(self)}>"


class NativeKCP:
    """Thin Python owner/facade for one upstream ``ikcpcb`` instance.

    The output callback receives one UDP payload as ``bytes``. Scheduling stays
    with the caller through :meth:`update` and :meth:`check`.
    """

    def __init__(
        self,
        conv: int,
        output: Callable[[bytes], None],
        config: KCPConfig | None = None,
    ) -> None:
        if not callable(output):
            raise TypeError("output must be callable")

        self.output = output
        self.config = config or KCPConfig()
        self._callback_error: (
            tuple[type[BaseException], BaseException, TracebackType | None] | None
        ) = None
        self._handle = ffi.new_handle(weakref.ref(self))
        self._native = lib.ikcp_create(_u32(conv), self._handle)
        if self._native == ffi.NULL:
            raise MemoryError("could not allocate KCP state")

        try:
            mtu = operator.index(self.config.mtu)
            mtu_status = lib.ikcp_setmtu(self._native, mtu)
            if mtu_status == -2:
                raise MemoryError("could not allocate KCP MTU buffer")
            if mtu_status != 0:
                raise ValueError(
                    f"MTU must be at least 50 bytes (got {self.config.mtu!r})"
                )

            lib.ikcp_wndsize(
                self._native,
                operator.index(self.config.snd_wnd),
                operator.index(self.config.rcv_wnd),
            )
            lib.ikcp_nodelay(
                self._native,
                operator.index(self.config.nodelay),
                operator.index(self.config.interval),
                operator.index(self.config.resend),
                operator.index(self.config.nc),
            )
            lib.ikcp_setoutput(self._native, _OUTPUT_CALLBACK)
        except BaseException:
            lib.ikcp_release(self._native)
            self._native = ffi.NULL
            raise

        self.fastresend = self.config.resend
        self.nocwnd = self.config.nc
        self.rcv_queue = _QueueView(self, "nrcv_que", "rcv_queue")
        self.rcv_buf = _QueueView(self, "nrcv_buf", "rcv_buf")
        self.snd_queue = _QueueView(self, "nsnd_que", "snd_queue")
        self.snd_buf = _QueueView(self, "nsnd_buf", "snd_buf")

    def __del__(self) -> None:
        native = getattr(self, "_native", ffi.NULL)
        if native != ffi.NULL:
            lib.ikcp_release(native)
            self._native = ffi.NULL

    def _ensure_open(self) -> None:
        if self._native == ffi.NULL:
            raise RuntimeError("KCP instance is closed")

    def _raise_callback_error(self) -> None:
        error = self._callback_error
        if error is None:
            return
        self._callback_error = None
        _, exception, traceback = error
        raise exception.with_traceback(traceback)

    def send(self, data: bytes) -> int:
        self._ensure_open()
        payload = bytes(data)
        if not payload:
            return -1
        buffer = ffi.from_buffer("const char[]", payload)
        status = int(lib.ikcp_send(self._native, buffer, len(payload)))
        # Recent upstream KCP returns the accepted byte count. This project has
        # always exposed 0 for success, and all callers rely on that convention.
        return 0 if status >= 0 else status

    def recv(self) -> bytes | None:
        self._ensure_open()
        size = int(lib.ikcp_peeksize(self._native))
        if size < 0:
            return None
        buffer = ffi.new("char[]", max(size, 1))
        received = int(lib.ikcp_recv(self._native, buffer, size))
        if received < 0:
            return None
        return bytes(ffi.buffer(buffer, received))

    def peeksize(self) -> int:
        self._ensure_open()
        return int(lib.ikcp_peeksize(self._native))

    def input(self, data: bytes) -> int:
        self._ensure_open()
        packet = bytes(data)
        if packet:
            buffer = ffi.from_buffer("const char[]", packet)
        else:
            buffer = ffi.NULL
        return int(lib.ikcp_input(self._native, buffer, len(packet)))

    def update(self, current_ms: int) -> None:
        self._ensure_open()
        lib.ikcp_update(self._native, _u32(current_ms))
        self._raise_callback_error()

    def flush(self) -> None:
        """Immediately emit queued segments using the current KCP timestamp."""
        self._ensure_open()
        # Upstream intentionally ignores flush() before the first update().
        # Temporarily mark the state initialized to retain the public behavior.
        was_updated = bool(self._native.updated)
        if not was_updated:
            self._native.updated = 1
        try:
            lib.ikcp_flush(self._native)
        finally:
            if not was_updated:
                self._native.updated = 0
        self._raise_callback_error()

    def check(self, current_ms: int) -> int:
        self._ensure_open()
        return int(lib.ikcp_check(self._native, _u32(current_ms)))

    def set_nodelay(self, nodelay: int, interval: int, resend: int, nc: int) -> None:
        self._ensure_open()
        lib.ikcp_nodelay(
            self._native,
            operator.index(nodelay),
            operator.index(interval),
            operator.index(resend),
            operator.index(nc),
        )
        if resend >= 0:
            self.fastresend = resend
        if nc >= 0:
            self.nocwnd = nc

    def wndsize(self, sndwnd: int, rcvwnd: int) -> None:
        self._ensure_open()
        lib.ikcp_wndsize(self._native, operator.index(sndwnd), operator.index(rcvwnd))

    @property
    def conv(self) -> int:
        self._ensure_open()
        return int(self._native.conv)

    @conv.setter
    def conv(self, value: int) -> None:
        self._ensure_open()
        self._native.conv = _u32(value)

    @property
    def mtu(self) -> int:
        self._ensure_open()
        return int(self._native.mtu)

    @property
    def mss(self) -> int:
        self._ensure_open()
        return int(self._native.mss)

    @property
    def snd_una(self) -> int:
        self._ensure_open()
        return int(self._native.snd_una)

    @property
    def snd_nxt(self) -> int:
        self._ensure_open()
        return int(self._native.snd_nxt)

    @property
    def rcv_nxt(self) -> int:
        self._ensure_open()
        return int(self._native.rcv_nxt)

    @property
    def snd_wnd(self) -> int:
        self._ensure_open()
        return int(self._native.snd_wnd)

    @property
    def rcv_wnd(self) -> int:
        self._ensure_open()
        return int(self._native.rcv_wnd)

    @property
    def rmt_wnd(self) -> int:
        self._ensure_open()
        return int(self._native.rmt_wnd)

    @property
    def current(self) -> int:
        self._ensure_open()
        return int(self._native.current)

    @property
    def interval(self) -> int:
        self._ensure_open()
        return int(self._native.interval)

    @property
    def nodelay(self) -> int:
        self._ensure_open()
        return int(self._native.nodelay)

    @property
    def updated(self) -> bool:
        self._ensure_open()
        return bool(self._native.updated)


def _output_callback(
    data: Any, length: int, _native: Any, user: Any
) -> int:  # pragma: no cover - exercised through native calls
    owner_ref = ffi.from_handle(user)
    owner = owner_ref()
    if owner is None:
        return -1
    if owner._callback_error is not None:
        return -1
    try:
        owner.output(bytes(ffi.buffer(data, length)))
    except BaseException:
        owner._callback_error = sys.exc_info()
        return -1
    return 0


_OUTPUT_CALLBACK = ffi.callback("ikcp_output_callback", _output_callback)
