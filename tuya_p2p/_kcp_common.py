"""Shared public contract for the interchangeable KCP implementations."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

IKCP_RTO_NDL = 30
IKCP_RTO_MIN = 100
IKCP_RTO_DEF = 200
IKCP_RTO_MAX = 60000
IKCP_CMD_PUSH = 81
IKCP_CMD_ACK = 82
IKCP_CMD_WASK = 83
IKCP_CMD_WINS = 84
IKCP_ASK_SEND = 1
IKCP_ASK_TELL = 2
IKCP_WND_SND = 32
IKCP_WND_RCV = 128
IKCP_MTU_DEF = 1400
IKCP_ACK_FAST = 3
IKCP_INTERVAL = 100
IKCP_OVERHEAD = 24
IKCP_DEADLINK = 20
IKCP_THRESH_INIT = 2
IKCP_THRESH_MIN = 2
UINT32_MASK = 0xFFFFFFFF

UPSTREAM_REPOSITORY = "https://github.com/skywind3000/kcp"
UPSTREAM_COMMIT = "b1a7a2101dcbb96017681a500d6b82bbe5a88766"


@dataclass(slots=True)
class KCPConfig:
    """KCP transport tuning shared by both implementations."""

    mtu: int = IKCP_MTU_DEF
    snd_wnd: int = IKCP_WND_SND
    rcv_wnd: int = IKCP_WND_RCV
    nodelay: int = 0
    interval: int = IKCP_INTERVAL
    resend: int = 0
    nc: int = 0


@runtime_checkable
class KCPImplementation(Protocol):
    """The small transport contract used by protocol code."""

    def send(self, data: bytes) -> int: ...
    def recv(self) -> bytes | None: ...
    def input(self, data: bytes) -> int: ...
    def update(self, current_ms: int) -> None: ...
    def flush(self) -> None: ...
    def check(self, current_ms: int) -> int: ...


OutputCallback = Callable[[bytes], None]
