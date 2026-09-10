import struct

import pytest

from tuya_p2p.kcp import (
    IKCP_CMD_PUSH,
    IKCP_OVERHEAD,
    KCP,
    KCPConfig,
    UPSTREAM_COMMIT,
    available_backends,
    get_default_backend,
    native_available,
    set_default_backend,
    using_backend,
)


@pytest.fixture(params=available_backends())
def backend(request):
    return request.param


def segment(*, conv=1, cmd=IKCP_CMD_PUSH, frg=0, sn=0, payload=b""):
    return (
        struct.pack("<IBBHIIII", conv, cmd, frg, 128, 10, sn, 0, len(payload)) + payload
    )


def test_send_preserves_status_convention_and_upstream_fragment_limit(backend):
    kcp = KCP(1, lambda _: None, KCPConfig(mtu=50, nc=1), backend=backend)

    assert kcp.send(b"") == -1
    assert kcp.send(b"x" * (kcp.mss * 127)) == 0

    too_large = KCP(1, lambda _: None, KCPConfig(mtu=50, nc=1), backend=backend)
    assert too_large.send(b"x" * (too_large.mss * 128)) == -2


def test_constructor_rejects_mtu_without_payload_capacity(backend):
    with pytest.raises(ValueError, match="MTU"):
        KCP(1, lambda _: None, KCPConfig(mtu=IKCP_OVERHEAD), backend=backend)

    with pytest.raises(ValueError, match="at least 50"):
        KCP(1, lambda _: None, KCPConfig(mtu=49), backend=backend)


@pytest.mark.parametrize(
    ("packet", "status"),
    [
        (b"short", -1),
        (segment(conv=2), -1),
        (segment(cmd=0xFF), -3),
        (segment(payload=b"abc")[:-1], -2),
    ],
)
def test_input_rejects_malformed_or_foreign_segments(backend, packet, status):
    assert KCP(1, lambda _: None, backend=backend).input(packet) == status


def test_receiver_buffers_gaps_and_delivers_messages_in_sequence(backend):
    kcp = KCP(1, lambda _: None, backend=backend)

    assert kcp.input(segment(sn=1, payload=b"second")) == 0
    assert kcp.recv() is None
    assert kcp.input(segment(sn=0, payload=b"first")) == 0

    assert kcp.recv() == b"first"
    assert kcp.recv() == b"second"


def test_check_reports_immediate_first_update_then_next_flush_deadline(backend):
    kcp = KCP(1, lambda _: None, KCPConfig(interval=30), backend=backend)

    assert kcp.check(500) == 500
    kcp.update(500)
    assert kcp.check(510) == 530


def test_backend_selection_and_upstream_revision_are_explicit():
    assert UPSTREAM_COMMIT == "b1a7a2101dcbb96017681a500d6b82bbe5a88766"
    assert KCP.__module__ == "tuya_p2p.kcp"
    assert type(KCP(1, lambda _: None, backend="python")).__name__ == "PythonKCP"
    assert type(KCP(1, lambda _: None)).__name__ == (
        "NativeKCP" if native_available() else "PythonKCP"
    )
    if native_available():
        assert type(KCP(1, lambda _: None, backend="native")).__name__ == "NativeKCP"
    else:
        with pytest.raises(RuntimeError, match="native KCP backend is unavailable"):
            KCP(1, lambda _: None, backend="native")
    with pytest.raises(ValueError, match="backend"):
        KCP(1, lambda _: None, backend="unknown")  # type: ignore[arg-type]


def test_process_default_backend_is_explicit_and_per_instance_wins():
    assert get_default_backend() == "auto"
    with using_backend("python"):
        assert get_default_backend() == "python"
        assert type(KCP(1, lambda _: None)).__name__ == "PythonKCP"
        if native_available():
            assert type(KCP(1, lambda _: None, backend="native")).__name__ == "NativeKCP"
    assert get_default_backend() == "auto"

    previous = set_default_backend("python")
    try:
        assert previous == "auto"
        assert type(KCP(1, lambda _: None)).__name__ == "PythonKCP"
    finally:
        set_default_backend(previous)


def test_flush_before_first_update_preserves_callback_semantics(backend):
    output = []
    kcp = KCP(1, output.append, KCPConfig(nc=1), backend=backend)

    assert kcp.send(b"immediate") == 0
    kcp.flush()

    assert len(output) == 1
    assert isinstance(output[0], bytes)
    assert not kcp.updated


def test_output_callback_errors_propagate_to_the_triggering_call(backend):
    def fail(_packet):
        raise LookupError("output failed")

    kcp = KCP(1, fail, KCPConfig(nc=1), backend=backend)
    assert kcp.send(b"payload") == 0

    with pytest.raises(LookupError, match="output failed"):
        kcp.update(0)


def test_receive_diagnostics_remain_available(backend):
    kcp = KCP(1, lambda _: None, backend=backend)

    assert kcp.input(segment(sn=1, payload=b"second")) == 0
    assert kcp.rcv_nxt == 0
    assert len(kcp.rcv_queue) == 0
    assert len(kcp.rcv_buf) == 1

    assert kcp.input(segment(sn=0, payload=b"first")) == 0
    assert kcp.rcv_nxt == 2
    assert len(kcp.rcv_queue) == 2
    assert len(kcp.rcv_buf) == 0


def test_bidirectional_fragmented_delivery_with_acknowledgements(backend):
    """Exercise the actual contract through lossless KCP datagram exchange."""
    outgoing_a: list[bytes] = []
    outgoing_b: list[bytes] = []
    config = KCPConfig(mtu=50, nodelay=1, interval=20, resend=2, nc=1)
    a = KCP(7, outgoing_a.append, config, backend=backend)
    b = KCP(7, outgoing_b.append, config, backend=backend)

    payload = b"fragmented payload " * 20
    assert a.send(payload) == 0
    for now in range(0, 500, 20):
        a.update(now)
        while outgoing_a:
            assert b.input(outgoing_a.pop(0)) == 0
        b.update(now)
        while outgoing_b:
            assert a.input(outgoing_b.pop(0)) == 0

    assert b.recv() == payload
    assert a.snd_una == a.snd_nxt


@pytest.mark.skipif(not native_available(), reason="native KCP extension is not built")
@pytest.mark.parametrize(
    "sender_backend, receiver_backend", [("native", "python"), ("python", "native")]
)
def test_native_and_python_backends_interoperate(sender_backend, receiver_backend):
    """KCP datagrams and ACKs are portable across the two implementations."""
    sender_output: list[bytes] = []
    receiver_output: list[bytes] = []
    config = KCPConfig(mtu=50, nodelay=1, interval=20, resend=2, nc=1)
    sender = KCP(9, sender_output.append, config, backend=sender_backend)
    receiver = KCP(9, receiver_output.append, config, backend=receiver_backend)
    payload = b"cross backend KCP " * 20
    assert sender.send(payload) == 0

    for now in range(0, 500, 20):
        sender.update(now)
        while sender_output:
            assert receiver.input(sender_output.pop(0)) == 0
        receiver.update(now)
        while receiver_output:
            assert sender.input(receiver_output.pop(0)) == 0

    assert receiver.recv() == payload
    assert sender.snd_una == sender.snd_nxt
