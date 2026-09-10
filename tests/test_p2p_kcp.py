import struct

import pytest

from tuya_p2p.kcp import (
    IKCP_CMD_PUSH,
    IKCP_OVERHEAD,
    KCP,
    KCPConfig,
    UPSTREAM_COMMIT,
)


def segment(*, conv=1, cmd=IKCP_CMD_PUSH, frg=0, sn=0, payload=b""):
    return (
        struct.pack("<IBBHIIII", conv, cmd, frg, 128, 10, sn, 0, len(payload)) + payload
    )


def test_send_preserves_status_convention_and_upstream_fragment_limit():
    kcp = KCP(1, lambda _: None, KCPConfig(mtu=50, nc=1))

    assert kcp.send(b"") == -1
    assert kcp.send(b"x" * (kcp.mss * 127)) == 0

    too_large = KCP(1, lambda _: None, KCPConfig(mtu=50, nc=1))
    assert too_large.send(b"x" * (too_large.mss * 128)) == -2


def test_constructor_rejects_mtu_without_payload_capacity():
    with pytest.raises(ValueError, match="MTU"):
        KCP(1, lambda _: None, KCPConfig(mtu=IKCP_OVERHEAD))

    with pytest.raises(ValueError, match="at least 50"):
        KCP(1, lambda _: None, KCPConfig(mtu=49))


@pytest.mark.parametrize(
    ("packet", "status"),
    [
        (b"short", -1),
        (segment(conv=2), -1),
        (segment(cmd=0xFF), -3),
        (segment(payload=b"abc")[:-1], -2),
    ],
)
def test_input_rejects_malformed_or_foreign_segments(packet, status):
    assert KCP(1, lambda _: None).input(packet) == status


def test_receiver_buffers_gaps_and_delivers_messages_in_sequence():
    kcp = KCP(1, lambda _: None)

    assert kcp.input(segment(sn=1, payload=b"second")) == 0
    assert kcp.recv() is None
    assert kcp.input(segment(sn=0, payload=b"first")) == 0

    assert kcp.recv() == b"first"
    assert kcp.recv() == b"second"


def test_check_reports_immediate_first_update_then_next_flush_deadline():
    kcp = KCP(1, lambda _: None, KCPConfig(interval=30))

    assert kcp.check(500) == 500
    kcp.update(500)
    assert kcp.check(510) == 530


def test_binding_is_pinned_to_the_vendored_upstream_revision():
    assert UPSTREAM_COMMIT == "b1a7a2101dcbb96017681a500d6b82bbe5a88766"
    assert KCP.__module__ == "tuya_p2p.kcp"
    assert type(KCP(1, lambda _: None)._native).__module__ == "_cffi_backend"


def test_flush_before_first_update_preserves_callback_semantics():
    output = []
    kcp = KCP(1, output.append, KCPConfig(nc=1))

    assert kcp.send(b"immediate") == 0
    kcp.flush()

    assert len(output) == 1
    assert isinstance(output[0], bytes)
    assert not kcp.updated


def test_output_callback_errors_propagate_to_the_triggering_call():
    def fail(_packet):
        raise LookupError("output failed")

    kcp = KCP(1, fail, KCPConfig(nc=1))
    assert kcp.send(b"payload") == 0

    with pytest.raises(LookupError, match="output failed"):
        kcp.update(0)


def test_native_receive_diagnostics_remain_available():
    kcp = KCP(1, lambda _: None)

    assert kcp.input(segment(sn=1, payload=b"second")) == 0
    assert kcp.rcv_nxt == 0
    assert len(kcp.rcv_queue) == 0
    assert len(kcp.rcv_buf) == 1

    assert kcp.input(segment(sn=0, payload=b"first")) == 0
    assert kcp.rcv_nxt == 2
    assert len(kcp.rcv_queue) == 2
    assert len(kcp.rcv_buf) == 0
