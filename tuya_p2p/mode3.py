from __future__ import annotations

import hmac
import os
from dataclasses import dataclass
from hashlib import sha1
from typing import Callable

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

BLOCK_SIZE = 16
HMAC_SIZE = 20


def _require_key(key: bytes) -> None:
    if len(key) != 16:
        raise ValueError(f"security mode 3 requires a 16-byte key, got {len(key)}")


def pkcs7_pad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    if block_size <= 0 or block_size >= 256:
        raise ValueError("invalid PKCS#7 block size")
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len


def pkcs7_unpad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    if not data or len(data) % block_size:
        raise ValueError("invalid PKCS#7 padded length")
    pad_len = data[-1]
    if pad_len == 0 or pad_len > block_size:
        raise ValueError("invalid PKCS#7 padding")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("invalid PKCS#7 padding")
    return data[:-pad_len]


def encrypt_application_payload(
    key: bytes,
    plaintext: bytes,
    *,
    iv: bytes | None = None,
    random_bytes: Callable[[int], bytes] = os.urandom,
) -> bytes:
    _require_key(key)
    if iv is None:
        iv = random_bytes(BLOCK_SIZE)
    if len(iv) != BLOCK_SIZE:
        raise ValueError("IV must be exactly 16 bytes")

    padded = pkcs7_pad(plaintext)
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    ciphertext = enc.update(padded) + enc.finalize()
    return iv + ciphertext


def decrypt_application_payload(key: bytes, payload: bytes) -> bytes:
    _require_key(key)
    if len(payload) < 32 or (len(payload) - BLOCK_SIZE) % BLOCK_SIZE:
        raise ValueError("invalid mode-3 application payload length")

    iv = payload[:BLOCK_SIZE]
    ciphertext = payload[BLOCK_SIZE:]
    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    padded = dec.update(ciphertext) + dec.finalize()
    return pkcs7_unpad(padded)


def sign_kcp_datagram(key: bytes, kcp_datagram: bytes) -> bytes:
    _require_key(key)
    return kcp_datagram + hmac.new(key, kcp_datagram, sha1).digest()


def verify_kcp_datagram(key: bytes, wire_datagram: bytes) -> bytes:
    _require_key(key)
    if len(wire_datagram) < HMAC_SIZE:
        raise ValueError("wire datagram is shorter than HMAC-SHA1")

    body = wire_datagram[:-HMAC_SIZE]
    supplied = wire_datagram[-HMAC_SIZE:]
    expected = hmac.new(key, body, sha1).digest()
    if not hmac.compare_digest(supplied, expected):
        raise ValueError("invalid mode-3 HMAC-SHA1")
    return body


@dataclass(slots=True, frozen=True)
class Mode3Codec:
    key: bytes

    def __post_init__(self) -> None:
        _require_key(self.key)

    def encrypt(self, plaintext: bytes, *, iv: bytes | None = None) -> bytes:
        return encrypt_application_payload(self.key, plaintext, iv=iv)

    def decrypt(self, payload: bytes) -> bytes:
        return decrypt_application_payload(self.key, payload)

    def sign(self, kcp_datagram: bytes) -> bytes:
        return sign_kcp_datagram(self.key, kcp_datagram)

    def verify(self, wire_datagram: bytes) -> bytes:
        return verify_kcp_datagram(self.key, wire_datagram)
