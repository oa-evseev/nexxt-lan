import hashlib
import hmac

import pytest

from tuya_p2p.mode3 import (
    Mode3Codec,
    decrypt_application_payload,
    encrypt_application_payload,
    pkcs7_pad,
    pkcs7_unpad,
    sign_kcp_datagram,
    verify_kcp_datagram,
)

KEY = bytes.fromhex("00112233445566778899aabbccddeeff")
IV = bytes.fromhex("ffeeddccbbaa99887766554433221100")


def test_application_roundtrip():
    plaintext = b"A" * 104
    payload = encrypt_application_payload(KEY, plaintext, iv=IV)
    assert len(payload) == 128
    assert payload[:16] == IV
    assert decrypt_application_payload(KEY, payload) == plaintext


def test_hmac_layout():
    body = b"kcp"
    wire = sign_kcp_datagram(KEY, body)
    assert wire[:-20] == body
    assert wire[-20:] == hmac.new(KEY, body, hashlib.sha1).digest()
    assert verify_kcp_datagram(KEY, wire) == body


@pytest.mark.parametrize("size", [0, 1, 15, 16, 17, 255])
def test_encryption_roundtrip_at_padding_boundaries(size):
    plaintext = bytes(range(256))[:size]
    payload = encrypt_application_payload(KEY, plaintext, iv=IV)

    assert payload[:16] == IV
    assert (len(payload) - 16) % 16 == 0
    assert decrypt_application_payload(KEY, payload) == plaintext


def test_random_iv_source_is_used_once_and_is_exposed_in_payload():
    calls = []

    def deterministic_random(size):
        calls.append(size)
        return IV

    payload = encrypt_application_payload(
        KEY, b"message", random_bytes=deterministic_random
    )

    assert calls == [16]
    assert payload.startswith(IV)


@pytest.mark.parametrize("key", [b"", b"x" * 15, b"x" * 17, b"x" * 32])
def test_mode3_rejects_non_aes128_keys(key):
    with pytest.raises(ValueError, match="16-byte key"):
        Mode3Codec(key)


@pytest.mark.parametrize("payload", [b"", b"x" * 16, b"x" * 31, b"x" * 33])
def test_decrypt_rejects_invalid_wire_lengths(payload):
    with pytest.raises(ValueError, match="payload length"):
        decrypt_application_payload(KEY, payload)


def test_decrypt_rejects_tampered_ciphertext_padding():
    payload = encrypt_application_payload(KEY, b"authenticated later", iv=IV)
    tampered = payload[:-1] + bytes([payload[-1] ^ 1])

    with pytest.raises(ValueError, match="padding"):
        decrypt_application_payload(KEY, tampered)


def test_hmac_verification_rejects_truncation_and_tampering():
    wire = sign_kcp_datagram(KEY, b"kcp payload")

    with pytest.raises(ValueError, match="shorter"):
        verify_kcp_datagram(KEY, wire[:19])
    with pytest.raises(ValueError, match="HMAC"):
        verify_kcp_datagram(KEY, wire[:-1] + bytes([wire[-1] ^ 1]))


def test_pkcs7_always_adds_a_block_and_validates_every_padding_byte():
    padded = pkcs7_pad(b"A" * 16)
    assert padded == b"A" * 16 + b"\x10" * 16
    assert pkcs7_unpad(padded) == b"A" * 16

    with pytest.raises(ValueError, match="padding"):
        pkcs7_unpad(b"A" * 14 + b"\x01\x02")
