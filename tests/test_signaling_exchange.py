import hashlib
import hmac
import json
import logging
import struct
from types import SimpleNamespace

import pytest

import nexxt_lan


def _session_key(client_nonce: bytes, device_nonce: bytes, local_key: bytes) -> bytes:
    """Match the established 3.4 AES-ECB nonce-XOR key derivation."""
    cipher = nexxt_lan.Cipher(
        nexxt_lan.algorithms.AES(local_key),
        nexxt_lan.modes.ECB(),
    ).encryptor()
    return (
        cipher.update(
            bytes(left ^ right for left, right in zip(client_nonce, device_nonce))
        )
        + cipher.finalize()
    )


class TimeoutSocket:
    def __init__(self, timeout=3.0):
        self.timeout = timeout
        self.timeouts = []

    def gettimeout(self):
        return self.timeout

    def settimeout(self, timeout):
        self.timeout = timeout
        self.timeouts.append(timeout)


def test_pump_signaling_uses_bounded_slices_and_restores_timeout(monkeypatch):
    sock = TimeoutSocket()
    state = nexxt_lan.SignalingState()
    clock = [10.0]
    receive_windows = []

    monkeypatch.setattr(nexxt_lan.time, "monotonic", lambda: clock[0])

    def fake_receive(_sock, _key, *, seconds, state, **_kwargs):
        receive_windows.append(seconds)
        clock[0] += seconds
        return False

    monkeypatch.setattr(nexxt_lan, "receive_signaling", fake_receive)

    result = nexxt_lan.pump_signaling_until(
        sock,
        b"key",
        deadline=10.12,
        state=state,
    )

    assert result is False
    assert receive_windows == pytest.approx([0.05, 0.05, 0.02])
    assert all(
        window <= nexxt_lan.SIGNALING_PUMP_SLICE_SECONDS for window in receive_windows
    )
    assert sock.timeout == 3.0


def test_generated_exchange_interleaves_candidates_with_rx_pumps(monkeypatch):
    events = []
    state = nexxt_lan.SignalingState()
    session = SimpleNamespace(local_key=b"key", offer={"header": {"type": "offer"}})
    candidates = [
        {"header": {"type": "candidate"}, "id": 1},
        {"header": {"type": "candidate"}, "id": 2},
    ]

    monkeypatch.setattr(
        nexxt_lan,
        "send_heartbeat",
        lambda _sock: events.append("heartbeat"),
    )

    tx_time = iter([100.0, 100.005, 100.025])

    def fake_send(_sock, _seq, message, _key, **_kwargs):
        events.append(f"tx:{message['header']['type']}:{message.get('id', 0)}")
        return next(tx_time)

    monkeypatch.setattr(nexxt_lan, "send_json", fake_send)

    def fake_pump_for(_sock, _key, *, seconds, state, **_kwargs):
        events.append(f"pump:{seconds:.3f}")
        if seconds == nexxt_lan.SIGNALING_CANDIDATE_PUMP_SECONDS:
            state.answer_sdp = "answer"
            state.camera_host = ("192.0.2.3", 12345)

    monkeypatch.setattr(nexxt_lan, "pump_signaling_for", fake_pump_for)
    monkeypatch.setattr(
        nexxt_lan,
        "pump_signaling_until",
        lambda *_args, **_kwargs: events.append("final-pump") or True,
    )
    monkeypatch.setattr(
        nexxt_lan,
        "flush_signaling_traces",
        lambda _traces: events.append("flush-traces"),
    )

    result = nexxt_lan.exchange_signaling(object(), session, candidates, state=state)

    assert result is state
    assert events == [
        "heartbeat",
        "tx:offer:0",
        f"pump:{nexxt_lan.SIGNALING_OFFER_PUMP_SECONDS:.3f}",
        "tx:candidate:1",
        f"pump:{nexxt_lan.SIGNALING_CANDIDATE_PUMP_SECONDS:.3f}",
        "tx:candidate:2",
        f"pump:{nexxt_lan.SIGNALING_CANDIDATE_PUMP_SECONDS:.3f}",
        "final-pump",
        "flush-traces",
    ]


def test_exchange_defers_full_tx_traces_until_after_initial_pump(monkeypatch):
    events = []
    state = nexxt_lan.SignalingState()
    session = SimpleNamespace(local_key=b"key", offer={"header": {"type": "offer"}})

    monkeypatch.setattr(nexxt_lan, "send_heartbeat", lambda _sock: None)

    def fake_send(_sock, seq, _message, _key, *, deferred_trace):
        events.append(f"send:{seq}")
        deferred_trace.append(("TX", seq, 0x20, b"encrypted", b"key", b"plain"))
        return 100.0 + seq / 1000.0

    monkeypatch.setattr(nexxt_lan, "send_json", fake_send)
    monkeypatch.setattr(
        nexxt_lan,
        "pump_signaling_for",
        lambda *_args, **_kwargs: events.append("pump"),
    )

    def fake_final_pump(*_args, state, **_kwargs):
        events.append("final-pump")
        state.answer_sdp = "answer"
        state.camera_host = ("192.0.2.3", 12345)
        return True

    monkeypatch.setattr(nexxt_lan, "pump_signaling_until", fake_final_pump)
    monkeypatch.setattr(
        nexxt_lan,
        "flush_signaling_traces",
        lambda traces: events.append(f"flush:{len(traces)}"),
    )

    nexxt_lan.exchange_signaling(
        object(),
        session,
        [{"header": {"type": "candidate"}}],
        state=state,
    )

    assert events == [
        "send:1",
        "pump",
        "send:2",
        "pump",
        "final-pump",
        "flush:2",
    ]


def test_send_json_writes_before_expensive_trace(monkeypatch):
    events = []

    class SendSocket:
        def sendall(self, frame):
            events.append(("send", frame))

    monkeypatch.setattr(nexxt_lan.lan, "aes_encrypt", lambda _plain, _key: b"cipher")
    monkeypatch.setattr(nexxt_lan.lan, "build_frame", lambda *_args: b"frame")
    monkeypatch.setattr(nexxt_lan.time, "monotonic", lambda: 12.5)
    monkeypatch.setattr(
        nexxt_lan,
        "log_signaling_frame",
        lambda *_args, **_kwargs: events.append(("trace", None)),
    )

    sent_at = nexxt_lan.send_json(
        SendSocket(),
        1,
        {"header": {"type": "offer"}},
        b"key",
    )

    assert sent_at == 12.5
    assert events == [("send", b"frame"), ("trace", None)]


def test_34_heartbeat_response_with_retcode_is_received():
    session_key = bytes.fromhex("00112233445566778899aabbccddeeff")
    transport = nexxt_lan.LanSignalingTransport("3.4", b"0123456789abcdef")
    transport.session_key = session_key
    inbound = transport.build_frame(0, 0x09, b"\0\0\0\0")

    class Socket:
        def __init__(self):
            self.inbound = bytearray(inbound)
            self.sent = []

        def recv(self, size):
            part = bytes(self.inbound[:size])
            del self.inbound[:size]
            return part

        def sendall(self, frame):
            self.sent.append(frame)

    sock = Socket()
    nexxt_lan.send_heartbeat(sock, transport=transport)
    assert transport.recv_frame.__self__ is transport
    assert len(sock.sent) == 1
    assert sock.sent[0] == transport.build_frame(0, 0x09, b"")


def test_34_first_post_handshake_frame_is_sequential_dps_query(monkeypatch):
    local_key = b"0123456789abcdef"
    client_nonce = b"c" * 16
    device_nonce = b"d" * 16
    session_key = _session_key(client_nonce, device_nonce, local_key)
    from nexxt import lan_framing

    monkeypatch.setattr(lan_framing.secrets, "token_bytes", lambda size: client_nonce)

    local_codec = nexxt_lan.LanSignalingTransport("3.4", local_key)
    handshake_plain = (
        device_nonce
        + hmac.new(
            local_key,
            client_nonce,
            hashlib.sha256,
        ).digest()
    )
    handshake_response = local_codec.build_frame(
        34371,
        0x04,
        b"\0\0\0\0" + nexxt_lan.lan.aes_encrypt(handshake_plain, local_key),
    )
    session_codec = nexxt_lan.LanSignalingTransport("3.4", local_key)
    session_codec.session_key = session_key
    dps = {"dps": {"1": True}}
    dps_response = session_codec.build_frame(
        34372,
        0x10,
        b"\0\0\0\0"
        + session_codec.encrypt_payload(
            0x10,
            b'{"dps":{"1":true}}',
        ),
    )

    class Socket:
        def __init__(self):
            self.inbound = bytearray(handshake_response + dps_response)
            self.sent = []

        def recv(self, size):
            part = bytes(self.inbound[:size])
            del self.inbound[:size]
            return part

        def sendall(self, frame):
            self.sent.append(frame)

    sock = Socket()
    transport = nexxt_lan.LanSignalingTransport("3.4", local_key)
    next_seq = transport.negotiate_session_key(sock, 1)
    decoded = nexxt_lan.exchange_34_dp_query(sock, next_seq, transport)

    headers = [struct.unpack(">IIII", frame[:16]) for frame in sock.sent]
    assert [(seq, cmd) for _prefix, seq, cmd, _length in headers] == [
        (1, 0x03),
        (2, 0x05),
        (3, 0x10),
    ]
    query_payload = sock.sent[-1][16:-36]
    assert transport.decrypt_payload(0x10, query_payload) == b"{}"
    assert decoded["json"] == dps


def test_preconnect_lifecycle_decodes_activate_response(caplog):
    caplog.set_level(logging.INFO)
    session_key = bytes.fromhex("00112233445566778899aabbccddeeff")
    transport = nexxt_lan.LanSignalingTransport("3.4", b"0123456789abcdef")
    transport.session_key = session_key
    response = json.dumps(
        {
            "header": {"type": "activate_resp"},
            "msg": {
                "handle": 1,
                "error": 0,
                "seq": 1,
            },
        },
        separators=(",", ":"),
    ).encode()
    inbound = transport.build_frame(
        50,
        0x20,
        b"\0\0\0\0" + transport.encrypt_payload(0x20, response),
    )

    class Socket:
        def __init__(self):
            self.inbound = bytearray(inbound)

        def recv(self, size):
            result = bytes(self.inbound[:size])
            del self.inbound[:size]
            return result

    assert nexxt_lan.receive_lifecycle_response(
        Socket(),
        transport,
        expected_type="activate_resp",
    )
    assert "type=activate_resp handle=1 error=0" in caplog.text


def test_preconnect_transport_ack_precedes_and_does_not_replace_activate_response(
    caplog,
):
    caplog.set_level(logging.INFO)
    session_key = bytes.fromhex("00112233445566778899aabbccddeeff")
    transport = nexxt_lan.LanSignalingTransport("3.4", b"0123456789abcdef")
    transport.session_key = session_key
    response = json.dumps(
        {
            "header": {"type": "activate_resp"},
            "msg": {"handle": 1, "error": 0, "seq": 1},
        },
        separators=(",", ":"),
    ).encode()
    inbound = transport.build_frame(50, 0x20, b"\0\0\0\0") + transport.build_frame(
        51,
        0x20,
        b"\0\0\0\0" + transport.encrypt_payload(0x20, response),
    )

    class Socket:
        def __init__(self):
            self.inbound = bytearray(inbound)

        def recv(self, size):
            result = bytes(self.inbound[:size])
            del self.inbound[:size]
            return result

    assert nexxt_lan.receive_lifecycle_response(
        Socket(),
        transport,
        expected_type="activate_resp",
    )
    assert "activate_resp transport ACK retcode=0" in caplog.text
    assert "type=activate_resp handle=1 error=0 seq=1" in caplog.text


def test_preconnect_activate_response_requires_error_zero():
    transport = nexxt_lan.LanSignalingTransport("3.4", b"0123456789abcdef")
    transport.session_key = bytes.fromhex("00112233445566778899aabbccddeeff")
    response = json.dumps(
        {
            "header": {"type": "activate_resp"},
            "msg": {"handle": 1, "error": 7, "seq": 1},
        },
        separators=(",", ":"),
    ).encode()
    inbound = transport.build_frame(
        50,
        0x20,
        b"\0\0\0\0" + transport.encrypt_payload(0x20, response),
    )

    class Socket:
        def __init__(self):
            self.inbound = bytearray(inbound)

        def recv(self, size):
            result = bytes(self.inbound[:size])
            del self.inbound[:size]
            return result

    assert not nexxt_lan.receive_lifecycle_response(
        Socket(),
        transport,
        expected_type="activate_resp",
    )


def test_preconnect_offer_has_only_the_required_profile_extensions():
    client = nexxt_lan.ClientConfig("client", "192.0.2.2", 3478)
    camera = nexxt_lan.CameraConfig(
        "example-preconnect-camera",
        "device",
        "192.0.2.3",
        6668,
        "0123456789abcdef",
        "password",
        "3.4",
    )

    offer = nexxt_lan.build_offer(
        client,
        camera,
        session_id="device1234suffix",
        trace_id="trace",
        ice_credentials=("user", "password"),
        aes_key=b"x" * 16,
        rtc_mode=nexxt_lan.RTCMode.PRECONNECT,
    )

    assert offer["header"]["is_pre"] == 1
    assert offer["header"]["p2p_skill"] == 1635
    assert offer["header"]["security_level"] == 3
    assert offer["msg"]["preconnect"] is True


def test_preconnect_activate_uses_prepared_session_identity_and_checks_response(
    monkeypatch,
):
    camera = nexxt_lan.CameraConfig(
        "example-preconnect-camera",
        "device",
        "192.0.2.3",
        6668,
        "0123456789abcdef",
        "password",
        "3.4",
    )
    session = nexxt_lan.PreparedSession(
        b"0123456789abcdef",
        {"header": {}},
        "device-session",
        "trace",
        "client",
        "pwd",
        "ufrag",
        b"x" * 16,
        b"a" * 104,
        camera,
        nexxt_lan.RTCMode.PRECONNECT,
    )
    state = nexxt_lan.SignalingState(next_seq=9)
    state.transport = nexxt_lan.LanSignalingTransport("3.4", session.local_key)
    sent = []
    monkeypatch.setattr(
        nexxt_lan,
        "send_json",
        lambda _sock, seq, obj, _key, **kwargs: sent.append((seq, obj, kwargs)),
    )
    accepted = []
    monkeypatch.setattr(
        nexxt_lan,
        "receive_lifecycle_response",
        lambda _sock, _transport, **kwargs: accepted.append(kwargs) or True,
    )

    nexxt_lan.activate_preconnect_session(object(), session, state)

    assert sent == [
        (
            9,
            nexxt_lan.build_preconnect_activate(session),
            {
                "transport": state.transport,
            },
        )
    ]
    assert accepted == [
        {
            "expected_type": "activate_resp",
            "expected_handle": 1,
            "expected_seq": 1,
        }
    ]
    assert state.next_seq == 10


def test_preconnect_activate_delay_is_applied_immediately_before_activate(monkeypatch):
    camera = nexxt_lan.CameraConfig(
        "example-preconnect-camera",
        "device",
        "192.0.2.3",
        6668,
        "0123456789abcdef",
        "password",
        "3.4",
    )
    session = nexxt_lan.PreparedSession(
        b"0123456789abcdef",
        {"header": {}},
        "device-session",
        "trace",
        "client",
        "pwd",
        "ufrag",
        b"x" * 16,
        b"a" * 104,
        camera,
        nexxt_lan.RTCMode.PRECONNECT,
    )
    state = nexxt_lan.SignalingState(next_seq=9)
    state.transport = nexxt_lan.LanSignalingTransport("3.4", session.local_key)
    events = []
    monkeypatch.setattr(
        nexxt_lan.time,
        "sleep",
        lambda seconds: events.append(("sleep", seconds)),
    )
    monkeypatch.setattr(
        nexxt_lan,
        "send_json",
        lambda *_args, **_kwargs: events.append(("activate",)),
    )
    monkeypatch.setattr(
        nexxt_lan,
        "receive_lifecycle_response",
        lambda *_args, **_kwargs: True,
    )

    nexxt_lan.activate_preconnect_session(
        object(),
        session,
        state,
        activate_delay_ms=25,
    )

    assert events == [("sleep", 0.025), ("activate",)]


def test_preconnect_activate_delay_does_not_apply_to_direct_mode(monkeypatch):
    camera = nexxt_lan.CameraConfig(
        "camera",
        "device",
        "192.0.2.3",
        6668,
        "0123456789abcdef",
        "password",
        "3.4",
    )
    session = nexxt_lan.PreparedSession(
        b"0123456789abcdef",
        {"header": {}},
        "device-session",
        "trace",
        "client",
        "pwd",
        "ufrag",
        b"x" * 16,
        b"a" * 104,
        camera,
    )
    state = nexxt_lan.SignalingState()
    state.transport = nexxt_lan.LanSignalingTransport("3.4", session.local_key)
    monkeypatch.setattr(
        nexxt_lan.time,
        "sleep",
        lambda _seconds: pytest.fail("direct mode slept"),
    )

    with pytest.raises(RuntimeError, match="requires preconnect RTC mode"):
        nexxt_lan.activate_preconnect_session(
            object(),
            session,
            state,
            activate_delay_ms=25,
        )


def _disconnect_session():
    return SimpleNamespace(
        local_key=b"0123456789abcdef",
        session_id="synthetic-session",
        trace_id="synthetic-trace",
        client_id="synthetic-client",
        camera=SimpleNamespace(device_id="synthetic-device"),
    )


def test_graceful_disconnect_sends_once_and_restores_socket_timeout(monkeypatch):
    sock = TimeoutSocket()
    session = _disconnect_session()
    state = nexxt_lan.SignalingState(
        next_seq=9,
        session_started=True,
        transport=object(),
    )
    sent = []
    received = []
    monkeypatch.setattr(
        nexxt_lan,
        "send_json",
        lambda *args, **kwargs: sent.append((args, kwargs)),
    )
    monkeypatch.setattr(
        nexxt_lan,
        "receive_signaling",
        lambda *args, **kwargs: received.append((args, kwargs)),
    )

    nexxt_lan.graceful_disconnect(sock, session, state)
    nexxt_lan.graceful_disconnect(sock, session, state)

    assert len(sent) == 1
    args, kwargs = sent[0]
    assert args[1] == 9
    assert args[2]["header"]["type"] == "disconnect"
    assert args[2]["header"]["to"] == "synthetic-device"
    assert kwargs["transport"] is state.transport
    assert len(received) == 1
    assert received[0][1]["acknowledge_disconnect"] is True
    assert state.next_seq == 10
    assert state.disconnect_sent is True
    assert sock.timeout == 3.0
    assert sock.timeouts == [0.25, 3.0]


def test_graceful_disconnect_is_noop_before_session_start_and_idempotent_on_error(
    monkeypatch,
):
    sock = TimeoutSocket()
    session = _disconnect_session()
    state = nexxt_lan.SignalingState(next_seq=4)
    calls = []

    def failing_send(*_args, **_kwargs):
        calls.append("send")
        raise OSError("synthetic disconnect failure")

    monkeypatch.setattr(nexxt_lan, "send_json", failing_send)
    nexxt_lan.graceful_disconnect(sock, session, state)
    assert calls == []

    state.session_started = True
    nexxt_lan.graceful_disconnect(sock, session, state)
    nexxt_lan.graceful_disconnect(sock, session, state)

    assert calls == ["send"]
    assert state.disconnect_sent is True
    assert state.next_seq == 4
