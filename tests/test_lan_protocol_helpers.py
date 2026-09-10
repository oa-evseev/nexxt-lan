import hashlib
import hmac
import struct
import uuid
import zlib

import pytest

import nexxt_lan

CLIENT = nexxt_lan.ClientConfig("test-client-456", "192.0.2.2", 3478)
CAMERA = nexxt_lan.CameraConfig(
    "example-direct-camera",
    "test-device-123",
    "192.0.2.3",
    6668,
    "0123456789abcdef",
    "test-password",
)


def test_session_number_is_decimal_prefix_after_device_id():
    assert (
        nexxt_lan.session_number_from_id("device1700000000suffix", "device")
        == 1700000000
    )

    with pytest.raises(RuntimeError, match="unexpected sessionId"):
        nexxt_lan.session_number_from_id("other123", "device")
    with pytest.raises(RuntimeError, match="cannot extract"):
        nexxt_lan.session_number_from_id("devicesuffix", "device")


def test_generated_session_id_has_timestamp_and_alphanumeric_suffix(monkeypatch):
    monkeypatch.setattr(nexxt_lan.time, "time", lambda: 1700000000.123)
    suffix = iter("AbCd1234")
    monkeypatch.setattr(nexxt_lan.secrets, "choice", lambda _alphabet: next(suffix))

    session_id = nexxt_lan.generate_session_id("abc")

    assert session_id == "abc1700000000123AbCd1234"
    assert session_id.startswith("abc")
    assert session_id[3:].startswith("1700000000123")
    assert set(session_id[3 + len("1700000000123") :]) <= set(nexxt_lan.ICE_ALPHABET)
    assert nexxt_lan.session_number_from_id(session_id, "abc") == 1700000000123


def test_generated_session_ids_are_fresh():
    assert nexxt_lan.generate_session_id("device") != nexxt_lan.generate_session_id(
        "device"
    )


def test_generated_trace_id_is_a_fresh_uuidv4():
    trace_id = nexxt_lan.generate_trace_id()

    parsed = uuid.UUID(trace_id)
    assert parsed.version == 4
    assert str(parsed) == trace_id
    assert trace_id != nexxt_lan.generate_trace_id()


def test_wire_trace_id_keeps_uuid_device_and_timestamp_shape(monkeypatch):
    monkeypatch.setattr(nexxt_lan.time, "time", lambda: 1700000000.123)
    base_trace_id = "00000000-0000-4000-8000-000000000001"

    trace_id = nexxt_lan.build_trace_id(
        base_trace_id=base_trace_id,
        dev_id="device",
    )

    assert trace_id == f"{base_trace_id}_device_1700000000123"


def test_generated_ice_credentials_use_safe_fixed_length_alphabet():
    ufrag, password = nexxt_lan.generate_ice_credentials()
    next_ufrag, next_password = nexxt_lan.generate_ice_credentials()

    assert len(ufrag) == 4
    assert len(password) == 24
    assert set(ufrag) <= set(nexxt_lan.ICE_ALPHABET)
    assert set(password) <= set(nexxt_lan.ICE_ALPHABET)
    assert (ufrag, password) != (next_ufrag, next_password)


def test_generated_session_aes_key_is_a_fresh_aes_128_key():
    key = nexxt_lan.generate_session_aes_key()
    next_key = nexxt_lan.generate_session_aes_key()

    assert isinstance(key, bytes)
    assert len(key) == 16
    assert len(key.hex()) == 32
    assert key != next_key


def test_offer_sdp_has_crlf_framing_and_required_session_values():
    session = {
        "devId": "device",
        "uid": "client-id",
    }
    aes_key = bytes.fromhex("00112233445566778899aabbccddeeff")

    sdp = nexxt_lan.build_offer_sdp(
        session=session,
        session_id="device456suffix",
        ice_credentials=("local-user", "local-password"),
        aes_key=aes_key,
    )

    assert sdp.endswith("\r\n")
    assert "\n" not in sdp.replace("\r\n", "")
    assert "o=- 456 1 IN IP4 127.0.0.1\r\n" in sdp
    assert nexxt_lan.require_sdp_attr(sdp, "ice-ufrag") == "local-user"
    assert nexxt_lan.require_sdp_attr(sdp, "aes-key") == aes_key.hex()


def test_offer_sdp_uses_explicit_session_scoped_ice_credentials():
    session = {
        "devId": "device",
        "uid": "client-id",
    }

    sdp = nexxt_lan.build_offer_sdp(
        session=session,
        session_id="device456suffix",
        ice_credentials=("Ab3X", "Z" * 24),
        aes_key=b"Z" * 16,
    )

    assert nexxt_lan.require_sdp_attr(sdp, "ice-ufrag") == "Ab3X"
    assert nexxt_lan.require_sdp_attr(sdp, "ice-pwd") == "Z" * 24


def test_prepare_session_generates_ice_pair_once_and_uses_sdp_values(monkeypatch):
    generated = ("Ab3X", "Z" * 24)
    calls = []
    offer = {
        "header": {"sessionid": "sid", "trace_id": "trace", "from": "client"},
        "msg": {
            "sdp": (
                "a=ice-ufrag:Ab3X\r\n"
                f"a=ice-pwd:{generated[1]}\r\n"
                "a=aes-key:00112233445566778899aabbccddeeff\r\n"
            ),
        },
    }
    monkeypatch.setattr(nexxt_lan, "generate_session_id", lambda dev_id: f"{dev_id}1x")
    monkeypatch.setattr(
        nexxt_lan,
        "generate_ice_credentials",
        lambda: calls.append("generate") or generated,
    )
    monkeypatch.setattr(
        nexxt_lan,
        "generate_session_aes_key",
        lambda: bytes.fromhex("00112233445566778899aabbccddeeff"),
    )
    monkeypatch.setattr(
        nexxt_lan,
        "build_offer",
        lambda *_args, **kwargs: calls.append(kwargs["ice_credentials"]) or offer,
    )
    monkeypatch.setattr(
        nexxt_lan, "build_auth_info", lambda *_args, **_kwargs: bytes(104)
    )

    session = nexxt_lan.prepare_session(client=CLIENT, camera=CAMERA, debug=False)

    assert calls == ["generate", generated]
    assert session.local_ufrag == generated[0]
    assert session.ice_password == generated[1]
    assert session.aes_key == bytes.fromhex("00112233445566778899aabbccddeeff")


def test_offer_sdp_requires_a_16_byte_local_aes_key():
    base = {
        "devId": "device",
        "uid": "client",
    }
    with pytest.raises(RuntimeError, match="16 raw bytes"):
        nexxt_lan.build_offer_sdp(
            ice_credentials=("u", "p"),
            session=base,
            session_id="device1x",
            aes_key=b"too short",
        )
    with pytest.raises(RuntimeError, match="16 raw bytes"):
        nexxt_lan.build_offer_sdp(
            session=base,
            session_id="device1x",
            ice_credentials=("u", "p"),
            aes_key="not bytes",
        )


def test_preview_startup_matches_canonical_plaintexts():
    auth = b"a" * 104
    startup = dict(nexxt_lan.build_preview_startup(auth))

    assert list(startup) == [
        "AUTH",
        "CMD10",
        "CMD21",
        "CMD2",
        "PREVIEW",
        "CMD6/0",
        "CMD6/4",
    ]
    assert startup["AUTH"] == auth
    assert startup["CMD10"].hex() == "7856341200000000000000000a0000000400000001000100"
    assert startup["CMD21"].endswith(b"}\x00")
    assert len(startup["CMD21"]) == 133
    assert startup["CMD2"] == nexxt_lan.build_command(2, 2, 0, b"\0" * 4)
    assert startup["PREVIEW"] == nexxt_lan.build_command(
        0x00010004, 9, 0, struct.pack("<II", 0, 4)
    )
    assert startup["CMD6/0"] == nexxt_lan.build_command(
        0x00010003, 6, 0, struct.pack("<II", 0, 0)
    )
    assert startup["CMD6/4"] == nexxt_lan.build_command(
        0x00010005, 6, 4, struct.pack("<II", 0, 4)
    )


def test_generated_offer_has_fixed_lan_contract():
    offer = nexxt_lan.build_offer(
        CLIENT,
        CAMERA,
        session_id="test-device-123456suffix",
        trace_id="00000000-0000-4000-8000-000000000001_test-device-123_1700000000123",
        ice_credentials=("local-user", "local-password"),
        aes_key=bytes.fromhex("00112233445566778899aabbccddeeff"),
    )

    assert list(offer["header"]) == [
        "from",
        "path",
        "sessionid",
        "to",
        "trace_id",
        "type",
    ]
    assert list(offer["msg"]) == ["sdp", "token"]
    assert (
        offer["header"]["trace_id"]
        == "00000000-0000-4000-8000-000000000001_test-device-123_1700000000123"
    )
    assert offer["msg"]["token"] == [
        {"urls": nexxt_lan.local_stun_url(CLIENT)},
    ]
    assert offer["header"]["sessionid"] == "test-device-123456suffix"
    assert "a=msid-semantic: WMS test-device-123456suffix\r\n" in offer["msg"]["sdp"]
    assert "legacy-session-id" not in offer["msg"]["sdp"]


def test_prepare_session_uses_selected_runtime_config(monkeypatch):
    monkeypatch.setattr(
        nexxt_lan, "build_auth_info", lambda *_args, **_kwargs: bytes(104)
    )

    session = nexxt_lan.prepare_session(client=CLIENT, camera=CAMERA, debug=False)

    assert list(session.offer["header"]) == [
        "from",
        "path",
        "sessionid",
        "to",
        "trace_id",
        "type",
    ]
    assert list(session.offer["msg"]) == ["sdp", "token"]
    assert session.offer["msg"]["token"] == [{"urls": nexxt_lan.local_stun_url(CLIENT)}]


def test_stun_binding_request_has_valid_integrity_and_fingerprint(monkeypatch):
    random_values = iter([b"t" * 12, b"c" * 8])
    monkeypatch.setattr(nexxt_lan.os, "urandom", lambda size: next(random_values))

    packet = nexxt_lan.make_stun_binding_request("remote", "local", "password")
    msg_type, body_len, cookie = struct.unpack(">HHI", packet[:8])

    assert (msg_type, body_len, cookie) == (1, len(packet) - 20, nexxt_lan.STUN_COOKIE)
    assert packet[8:20] == b"t" * 12

    mi_pos = packet.index(struct.pack(">HH", 0x0008, 20), 20)
    supplied_mi = packet[mi_pos + 4 : mi_pos + 24]
    mi_header = struct.pack(">HHI12s", 1, mi_pos - 20 + 24, cookie, b"t" * 12)
    assert (
        supplied_mi
        == hmac.new(b"password", mi_header + packet[20:mi_pos], hashlib.sha1).digest()
    )

    fingerprint = struct.unpack(">I", packet[-4:])[0]
    assert fingerprint == (zlib.crc32(packet[:-8]) & 0xFFFFFFFF) ^ 0x5354554E


def test_stun_success_echoes_transaction_and_encodes_xor_mapped_address():
    request = struct.pack(">HHI12s", 1, 0, nexxt_lan.STUN_COOKIE, b"x" * 12)
    response = nexxt_lan.stun_success(request, ("192.0.2.1", 54321), "password")

    assert len(response) == 76
    assert response[8:20] == b"x" * 12
    xor_port = struct.unpack(">H", response[26:28])[0]
    assert xor_port ^ (nexxt_lan.STUN_COOKIE >> 16) == 54321
    assert nexxt_lan.stun_success(b"short", ("192.0.2.1", 1), "password") is None
