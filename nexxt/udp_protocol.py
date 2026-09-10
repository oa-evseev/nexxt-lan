"""Structural parsing for incoming STUN and KCP UDP datagrams."""

from __future__ import annotations

import enum
import struct
import time
from dataclasses import dataclass, field
from typing import Callable

STUN_MAGIC_COOKIE = b"\x21\x12\xa4\x42"

STUN_BINDING_REQUEST = 0x0001
STUN_BINDING_SUCCESS = 0x0101
STUN_BINDING_ERROR = 0x0111

STUN_ATTR_ERROR_CODE = 0x0009
STUN_ATTR_XOR_MAPPED_ADDRESS = 0x0020
STUN_ATTR_USE_CANDIDATE = 0x0025


class EventType(enum.Enum):
    KEEPALIVE = "KEEPALIVE"
    BINDING_REQUEST = "BINDING_REQUEST"
    BINDING_SUCCESS = "BINDING_SUCCESS"
    STUN_ERROR = "STUN_ERROR"
    OTHER_STUN = "OTHER_STUN"
    NON_STUN = "NON_STUN"
    INVALID = "INVALID"


@dataclass
class Event:
    type: EventType
    addr: tuple[str, int]

    stun_type: int | None = None
    txid: bytes | None = None

    use_candidate: bool = False
    error_code: int | None = None

    payload: bytes | None = None
    reason: str | None = None

    kcp: KcpPacket | None = None


@dataclass
class ClientState:
    seen_udp: int = 0
    seen_stun: int = 0
    seen_binding_requests: int = 0
    seen_binding_success: int = 0
    invalid_packets: int = 0

    last_rx_at: float | None = None
    last_stun_at: float | None = None

    nominated_peer: tuple[str, int] | None = None

    # Optional event queue for higher layers.
    events: list[Event] = field(default_factory=list)


@dataclass
class StunAttribute:
    type: int
    value: bytes


@dataclass
class StunMessage:
    type: int
    txid: bytes
    attributes: list[StunAttribute]


@dataclass
class ParseResult:
    ok: bool
    message: StunMessage | None = None
    reason: str | None = None


IntegrityValidator = Callable[
    [bytes, StunMessage, ClientState],
    bool,
]


def accept_without_extra_validation(
    data: bytes,
    msg: StunMessage,
    state: ClientState,
) -> bool:
    """
    Structural validation only.

    Replace this with the client's actual integrity checker when needed.
    """
    return True


def looks_like_stun(data: bytes) -> bool:
    return len(data) >= 20 and data[4:8] == STUN_MAGIC_COOKIE


def parse_stun(data: bytes) -> ParseResult:
    if len(data) < 20:
        return ParseResult(
            ok=False,
            reason="short STUN header",
        )

    msg_type, msg_len = struct.unpack(
        ">HH",
        data[:4],
    )

    if data[4:8] != STUN_MAGIC_COOKIE:
        return ParseResult(
            ok=False,
            reason="bad STUN magic cookie",
        )

    expected_len = 20 + msg_len

    if expected_len != len(data):
        return ParseResult(
            ok=False,
            reason=(
                f"STUN length mismatch: " f"header={expected_len}, actual={len(data)}"
            ),
        )

    if msg_len & 3:
        return ParseResult(
            ok=False,
            reason="STUN message length is not 4-byte aligned",
        )

    txid = data[8:20]

    attrs: list[StunAttribute] = []
    pos = 20

    while pos < expected_len:
        if pos + 4 > expected_len:
            return ParseResult(
                ok=False,
                reason="truncated STUN attribute header",
            )

        attr_type, attr_len = struct.unpack(
            ">HH",
            data[pos : pos + 4],
        )
        pos += 4

        value_end = pos + attr_len

        if value_end > expected_len:
            return ParseResult(
                ok=False,
                reason=(f"truncated STUN attribute " f"type=0x{attr_type:04x}"),
            )

        attrs.append(
            StunAttribute(
                type=attr_type,
                value=data[pos:value_end],
            )
        )

        padded_len = (attr_len + 3) & ~3
        pos += padded_len

        if pos > expected_len:
            return ParseResult(
                ok=False,
                reason="STUN attribute padding exceeds packet",
            )

    return ParseResult(
        ok=True,
        message=StunMessage(
            type=msg_type,
            txid=txid,
            attributes=attrs,
        ),
    )


def stun_has_attribute(
    msg: StunMessage,
    attr_type: int,
) -> bool:
    return any(attr.type == attr_type for attr in msg.attributes)


def stun_get_attribute(
    msg: StunMessage,
    attr_type: int,
) -> StunAttribute | None:
    for attr in msg.attributes:
        if attr.type == attr_type:
            return attr

    return None


def parse_stun_error_code(
    msg: StunMessage,
) -> int | None:
    attr = stun_get_attribute(
        msg,
        STUN_ATTR_ERROR_CODE,
    )

    if attr is None:
        return None

    if len(attr.value) < 4:
        return None

    error_class = attr.value[2] & 0x07
    error_number = attr.value[3]

    if not 3 <= error_class <= 6:
        return None

    return error_class * 100 + error_number


def handle_udp_datagram(
    data: bytes,
    addr: tuple[str, int],
    state: ClientState,
    *,
    validate_integrity: IntegrityValidator = accept_without_extra_validation,
    now: float | None = None,
) -> Event:
    """
    Parse one UDP datagram, validate it, update state, and return one event.

    Important invariant:
    protocol-specific state is changed only after successful validation.
    """
    if now is None:
        now = time.monotonic()

    state.seen_udp += 1
    state.last_rx_at = now

    if not looks_like_stun(data):
        kcp = parse_kcp_datagram(data)

        if kcp is not None:
            event = Event(
                type=EventType.KCP,
                addr=addr,
                payload=data,
                kcp=kcp,
            )
            state.events.append(event)
            return event

        event = Event(
            type=EventType.NON_STUN,
            addr=addr,
            payload=data,
        )
        state.events.append(event)
        return event

    parsed = parse_stun(data)

    if not parsed.ok:
        state.invalid_packets += 1

        event = Event(
            type=EventType.INVALID,
            addr=addr,
            reason=parsed.reason,
        )
        state.events.append(event)
        return event

    msg = parsed.message
    assert msg is not None

    if not validate_integrity(
        data,
        msg,
        state,
    ):
        state.invalid_packets += 1

        event = Event(
            type=EventType.INVALID,
            addr=addr,
            stun_type=msg.type,
            txid=msg.txid,
            reason="integrity validation failed",
        )
        state.events.append(event)
        return event

    state.seen_stun += 1
    state.last_stun_at = now

    if msg.type == STUN_BINDING_REQUEST:
        state.seen_binding_requests += 1

        use_candidate = stun_has_attribute(
            msg,
            STUN_ATTR_USE_CANDIDATE,
        )

        if use_candidate:
            state.nominated_peer = addr

        event = Event(
            type=EventType.BINDING_REQUEST,
            addr=addr,
            stun_type=msg.type,
            txid=msg.txid,
            use_candidate=use_candidate,
        )

    elif msg.type == STUN_BINDING_SUCCESS:
        state.seen_binding_success += 1

        event = Event(
            type=EventType.BINDING_SUCCESS,
            addr=addr,
            stun_type=msg.type,
            txid=msg.txid,
        )

    elif msg.type == STUN_BINDING_ERROR:
        event = Event(
            type=EventType.STUN_ERROR,
            addr=addr,
            stun_type=msg.type,
            txid=msg.txid,
            error_code=parse_stun_error_code(msg),
        )

    else:
        event = Event(
            type=EventType.OTHER_STUN,
            addr=addr,
            stun_type=msg.type,
            txid=msg.txid,
        )

    state.events.append(event)
    return event


@dataclass
class KcpPacket:
    conv: int
    cmd: int
    frg: int
    wnd: int
    ts: int
    sn: int
    una: int
    payload: bytes
    trailer: bytes


def parse_kcp_datagram(data: bytes):
    if len(data) < 24:
        return None

    (
        conv,
        cmd,
        frg,
        wnd,
        ts,
        sn,
        una,
        payload_len,
    ) = struct.unpack("<IBBHIIII", data[:24])

    expected = 24 + payload_len + 20

    if len(data) != expected:
        return None

    payload = data[24 : 24 + payload_len]
    trailer = data[24 + payload_len :]

    return KcpPacket(
        conv=conv,
        cmd=cmd,
        frg=frg,
        wnd=wnd,
        ts=ts,
        sn=sn,
        una=una,
        payload=payload,
        trailer=trailer,
    )


class EventType(enum.Enum):
    KEEPALIVE = "KEEPALIVE"
    BINDING_REQUEST = "BINDING_REQUEST"
    BINDING_SUCCESS = "BINDING_SUCCESS"
    STUN_ERROR = "STUN_ERROR"
    OTHER_STUN = "OTHER_STUN"
    KCP = "KCP"
    NON_STUN = "NON_STUN"
    INVALID = "INVALID"
