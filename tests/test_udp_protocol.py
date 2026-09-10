import struct

import pytest

from nexxt.udp_protocol import (
    STUN_ATTR_ERROR_CODE,
    STUN_ATTR_USE_CANDIDATE,
    STUN_BINDING_ERROR,
    STUN_BINDING_REQUEST,
    STUN_BINDING_SUCCESS,
    STUN_MAGIC_COOKIE,
    ClientState,
    EventType,
    handle_udp_datagram,
    parse_kcp_datagram,
    parse_stun,
)

TXID = bytes.fromhex("00112233445566778899aabb")
ADDR = ("192.0.2.10", 5000)


def stun_attr(attr_type, value):
    padding = b"\x00" * ((-len(value)) % 4)
    return struct.pack(">HH", attr_type, len(value)) + value + padding


def stun_message(msg_type, *attributes):
    body = b"".join(attributes)
    return struct.pack(">HH", msg_type, len(body)) + STUN_MAGIC_COOKIE + TXID + body


def kcp_wire(payload=b"data", *, conv=0x11223344):
    header = struct.pack("<IBBHIIII", conv, 81, 0, 128, 10, 2, 1, len(payload))
    return header + payload + b"h" * 20


def test_parse_stun_preserves_unknown_attributes_and_padding():
    packet = stun_message(STUN_BINDING_REQUEST, stun_attr(0x7777, b"abc"))

    result = parse_stun(packet)

    assert result.ok
    assert result.message.txid == TXID
    assert [(attr.type, attr.value) for attr in result.message.attributes] == [
        (0x7777, b"abc")
    ]


@pytest.mark.parametrize(
    ("packet", "reason"),
    [
        (b"short", "short STUN header"),
        (b"\x00\x01\x00\x00bad!" + b"x" * 12, "bad STUN magic cookie"),
        (
            struct.pack(">HH", STUN_BINDING_REQUEST, 4) + STUN_MAGIC_COOKIE + TXID,
            "length mismatch",
        ),
        (
            struct.pack(">HH", STUN_BINDING_REQUEST, 2)
            + STUN_MAGIC_COOKIE
            + TXID
            + b"xx",
            "not 4-byte aligned",
        ),
        (
            stun_message(STUN_BINDING_REQUEST, struct.pack(">HH", 1, 8) + b"1234"),
            "truncated STUN attribute",
        ),
    ],
)
def test_parse_stun_rejects_structurally_invalid_packets(packet, reason):
    result = parse_stun(packet)
    assert not result.ok
    assert reason in result.reason


def test_binding_nomination_updates_state_only_after_integrity_validation():
    packet = stun_message(STUN_BINDING_REQUEST, stun_attr(STUN_ATTR_USE_CANDIDATE, b""))
    rejected = ClientState()

    event = handle_udp_datagram(
        packet, ADDR, rejected, validate_integrity=lambda *_: False, now=12.5
    )
    assert event.type is EventType.INVALID
    assert rejected.seen_udp == 1
    assert rejected.invalid_packets == 1
    assert rejected.seen_stun == 0
    assert rejected.nominated_peer is None

    accepted = ClientState()
    event = handle_udp_datagram(packet, ADDR, accepted, now=13.0)
    assert event.type is EventType.BINDING_REQUEST
    assert event.use_candidate
    assert accepted.nominated_peer == ADDR
    assert accepted.seen_binding_requests == 1
    assert accepted.last_stun_at == 13.0
    assert accepted.events == [event]


def test_success_and_error_responses_update_distinct_state():
    state = ClientState()
    success = handle_udp_datagram(stun_message(STUN_BINDING_SUCCESS), ADDR, state)
    error_value = b"\x00\x00\x04\x04Not Found"
    error = handle_udp_datagram(
        stun_message(STUN_BINDING_ERROR, stun_attr(STUN_ATTR_ERROR_CODE, error_value)),
        ADDR,
        state,
    )

    assert success.type is EventType.BINDING_SUCCESS
    assert error.type is EventType.STUN_ERROR
    assert error.error_code == 404
    assert state.seen_binding_success == 1
    assert state.seen_stun == 2


def test_non_stun_data_is_classified_as_kcp_only_for_complete_wire_layout():
    state = ClientState()
    wire = kcp_wire(b"payload")

    event = handle_udp_datagram(wire, ADDR, state, now=20)
    assert event.type is EventType.KCP
    assert event.kcp.conv == 0x11223344
    assert event.kcp.payload == b"payload"
    assert event.kcp.trailer == b"h" * 20
    assert state.seen_stun == 0
    assert state.last_rx_at == 20

    assert parse_kcp_datagram(wire[:-1]) is None
    assert handle_udp_datagram(wire[:-1], ADDR, state).type is EventType.NON_STUN
