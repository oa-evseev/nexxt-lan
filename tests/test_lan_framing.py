import hashlib
import hmac
import struct
import zlib

import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from nexxt import lan_framing


def _session_key(client_nonce: bytes, device_nonce: bytes, local_key: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(local_key), modes.ECB()).encryptor()
    xor_nonce = bytes(left ^ right for left, right in zip(client_nonce, device_nonce))
    return cipher.update(xor_nonce) + cipher.finalize()


def test_33_transport_keeps_legacy_frame_and_cipher_path(monkeypatch):
    calls = []
    transport = lan_framing.LanSignalingTransport("3.3", b"0123456789abcdef")
    monkeypatch.setattr(
        lan_framing.lan,
        "aes_encrypt",
        lambda plain, key: calls.append(("encrypt", plain, key)) or b"cipher",
    )
    monkeypatch.setattr(
        lan_framing.lan,
        "build_frame",
        lambda seq, cmd, payload: calls.append(("frame", seq, cmd, payload))
        or b"frame",
    )

    assert (
        transport.build_frame(7, 0x20, transport.encrypt_signaling(b"json")) == b"frame"
    )
    assert calls == [
        ("encrypt", b"json", b"0123456789abcdef"),
        ("frame", 7, 0x20, b"cipher"),
    ]


def test_33_heartbeat_keeps_legacy_crc32_trailer():
    frame = lan_framing.LanSignalingTransport("3.3", b"0123456789abcdef").build_frame(
        0, 0x09, b""
    )

    assert len(frame) == 24
    assert struct.unpack(">I", frame[12:16])[0] == 8
    assert frame[-4:] == b"\0\0\xaa\x55"
    assert frame[-8:-4] == struct.pack(">I", zlib.crc32(frame[:16]) & 0xFFFFFFFF)


def test_34_heartbeat_uses_empty_payload_and_session_hmac_trailer():
    session_key = bytes.fromhex("00112233445566778899aabbccddeeff")
    transport = lan_framing.LanSignalingTransport("3.4", b"0123456789abcdef")
    transport.session_key = session_key

    frame = transport.build_frame(0, 0x09, b"")
    header = struct.pack(">IIII", 0x000055AA, 0, 0x09, 36)
    expected_hmac = hmac.new(session_key, header, hashlib.sha256).digest()

    assert frame == header + expected_hmac + struct.pack(">I", 0x0000AA55)
    assert frame[-8:-4] != struct.pack(">I", zlib.crc32(header) & 0xFFFFFFFF)
    assert (
        lan_framing.lan.aes_decrypt(transport.encrypt_payload(0x20, b"{}"), session_key)
        == b"{}"
    )


@pytest.mark.parametrize("cmd", [0x10, 0x20])
def test_34_commands_use_session_hmac_framing(cmd):
    session_key = bytes.fromhex("00112233445566778899aabbccddeeff")
    transport = lan_framing.LanSignalingTransport("3.4", b"0123456789abcdef")
    transport.session_key = session_key
    frame = transport.build_frame(7, cmd, transport.encrypt_payload(cmd, b"{}"))

    assert frame[-4:] == b"\0\0\xaa\x55"
    assert frame[-36:-4] == hmac.new(session_key, frame[:-36], hashlib.sha256).digest()


def test_34_receive_rejects_tampered_hmac():
    transport = lan_framing.LanSignalingTransport("3.4", b"0123456789abcdef")
    inbound = bytearray(transport.build_frame(1, 0x09, b""))
    inbound[-5] ^= 1

    class Socket:
        def recv(self, size):
            result = bytes(inbound[:size])
            del inbound[:size]
            return result

    with pytest.raises(ValueError, match="HMAC"):
        transport.recv_frame(Socket())


def test_34_negotiation_derives_and_installs_session_key(monkeypatch):
    local_key = b"0123456789abcdef"
    client_nonce = b"c" * 16
    device_nonce = b"d" * 16
    monkeypatch.setattr(lan_framing.secrets, "token_bytes", lambda _size: client_nonce)
    response_plain = (
        device_nonce + hmac.new(local_key, client_nonce, hashlib.sha256).digest()
    )
    response_payload = b"\0\0\0\0" + lan_framing.lan.aes_encrypt(
        response_plain, local_key
    )
    inbound = lan_framing.LanSignalingTransport("3.4", local_key).build_frame(
        1, 4, response_payload
    )

    class Socket:
        def __init__(self):
            self.inbound = bytearray(inbound)
            self.sent = []

        def recv(self, size):
            result = bytes(self.inbound[:size])
            del self.inbound[:size]
            return result

        def sendall(self, frame):
            self.sent.append(frame)

    sock = Socket()
    transport = lan_framing.LanSignalingTransport("3.4", local_key)

    assert transport.negotiate_session_key(sock, 12101) == 12103
    assert [int.from_bytes(frame[8:12], "big") for frame in sock.sent] == [3, 5]
    assert [int.from_bytes(frame[4:8], "big") for frame in sock.sent] == [12101, 12102]
    assert transport.key == _session_key(client_nonce, device_nonce, local_key)


def test_34_live_decoder_preserves_d1_optional_marker_behavior():
    transport = lan_framing.LanSignalingTransport("3.4", b"0123456789abcdef")
    payload = b"\0\0\0\0" + transport.encrypt_payload(
        0x20, transport._PROTOCOL_HEADER + b'{"answer":true}'
    )

    assert "decode_error" in transport.decode_json_payload(0x20, payload)
