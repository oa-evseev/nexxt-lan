"""Tuya LAN 3.3/3.4 TCP framing and payload cryptography.

This module deliberately has no knowledge of RTC message types or lifecycle.
It works only with LAN command numbers and byte payloads, using the packaged
3.3 helpers in :mod:`nexxt.lan33`.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import secrets
import socket
import struct
from typing import Optional

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from nexxt import lan33 as lan

LOG = logging.getLogger(__name__)


class LanSignalingTransport:
    """Protocol-version boundary for TCP LAN frames and encrypted payloads."""

    _PREFIX = 0x000055AA
    _SUFFIX = 0x0000AA55
    _SESSION_START = 3
    _SESSION_RESPONSE = 4
    _SESSION_FINISH = 5
    _PROTOCOL_HEADER = b"3.4" + b"\0" * 12
    _NO_PROTOCOL_HEADER_COMMANDS = frozenset(
        {
            0x03,
            0x04,
            0x05,
            0x09,
            0x0A,
            0x10,
            0x12,
            0x20,
            0x40,
        }
    )

    def __init__(self, protocol: str, local_key: bytes) -> None:
        if protocol not in {"3.3", "3.4"}:
            raise RuntimeError(
                f"unsupported lan_protocol {protocol!r} (supported: 3.3, 3.4)"
            )
        if protocol == "3.4" and len(local_key) != 16:
            raise RuntimeError("Tuya LAN local_key must be exactly 16 bytes")
        self.protocol = protocol
        self._local_key = local_key
        self.session_key = local_key

    @property
    def key(self) -> bytes:
        return self.session_key

    def build_frame(self, seq: int, cmd: int, payload: bytes) -> bytes:
        if self.protocol == "3.3":
            return lan.build_frame(seq, cmd, payload)
        header = struct.pack(">IIII", self._PREFIX, seq, cmd, len(payload) + 36)
        signed = header + payload
        return (
            signed
            + hmac.new(self.session_key, signed, hashlib.sha256).digest()
            + struct.pack(">I", self._SUFFIX)
        )

    def recv_frame(self, sock: socket.socket) -> tuple[int, int, bytes]:
        if self.protocol == "3.3":
            return lan.recv_frame(sock)
        header = lan.recv_exact(sock, 16)
        prefix, seq, cmd, length = struct.unpack(">IIII", header)
        if prefix != self._PREFIX:
            raise ValueError(f"bad prefix: 0x{prefix:08x}")
        if length < 36:
            raise ValueError(f"bad Tuya 3.4 frame length: {length}")
        rest = lan.recv_exact(sock, length)
        payload, received_mac, suffix = (
            rest[:-36],
            rest[-36:-4],
            struct.unpack(">I", rest[-4:])[0],
        )
        if suffix != self._SUFFIX:
            raise ValueError(f"bad suffix: 0x{suffix:08x}")
        expected_mac = hmac.new(
            self.session_key, header + payload, hashlib.sha256
        ).digest()
        if not hmac.compare_digest(received_mac, expected_mac):
            raise ValueError("bad Tuya 3.4 frame HMAC")
        return seq, cmd, payload

    def encrypt_payload(self, cmd: int, plaintext: bytes) -> bytes:
        if self.protocol == "3.3":
            return lan.aes_encrypt(plaintext, self.session_key)
        if cmd not in self._NO_PROTOCOL_HEADER_COMMANDS:
            plaintext = self._PROTOCOL_HEADER + plaintext
        return lan.aes_encrypt(plaintext, self.session_key)

    def decrypt_payload(self, cmd: int, ciphertext: bytes) -> bytes:
        plain = lan.aes_decrypt(ciphertext, self.session_key)
        if self.protocol == "3.4" and cmd not in self._NO_PROTOCOL_HEADER_COMMANDS:
            if not plain.startswith(self._PROTOCOL_HEADER):
                raise ValueError(
                    "Tuya 3.4 signaling payload is missing its protocol header"
                )
            return plain[len(self._PROTOCOL_HEADER) :]
        return plain

    def encrypt_signaling(self, plaintext: bytes) -> bytes:
        return self.encrypt_payload(0x20, plaintext)

    def decrypt_signaling(self, ciphertext: bytes) -> bytes:
        return self.decrypt_payload(0x20, ciphertext)

    def decode_camera_payload(self, payload: bytes) -> Optional[dict]:
        if self.protocol == "3.3":
            return lan.decode_camera_payload(payload, self.session_key)
        return self.decode_json_payload(0x20, payload)

    def decode_json_payload(self, cmd: int, payload: bytes) -> Optional[dict]:
        """Decode a 3.4 JSON response with its optional four-byte retcode.

        The current behavior is deliberately preserved: cmd 0x20 remains in
        the no-header set, so an optional 15-byte marker is not removed by the
        live decoder.
        """
        candidates: list[tuple[Optional[int], bytes]] = []
        if len(payload) >= 4:
            candidates.append((struct.unpack(">I", payload[:4])[0], payload[4:]))
        candidates.append((None, payload))

        last_error: Optional[Exception] = None
        for retcode, ciphertext in candidates:
            if not ciphertext or len(ciphertext) % 16:
                continue
            try:
                plain = self.decrypt_payload(cmd, ciphertext)
                decoded = {"json": json.loads(plain.decode())}
                if retcode is not None:
                    decoded["retcode"] = retcode
                return decoded
            except Exception as exc:
                last_error = exc

        if last_error is None:
            return None
        return {"decode_error": str(last_error), "raw_prefix": payload[:64].hex()}

    def negotiate_session_key(self, sock: socket.socket, next_seq: int = 1) -> int:
        """Perform the established Tuya 3.4 three-message key negotiation."""
        if self.protocol == "3.3":
            return next_seq
        client_nonce = secrets.token_bytes(16)
        start_payload = self.encrypt_payload(self._SESSION_START, client_nonce)
        sock.sendall(self.build_frame(next_seq, self._SESSION_START, start_payload))
        next_seq += 1
        _seq, cmd, response = self.recv_frame(sock)
        if cmd != self._SESSION_RESPONSE or len(response) < 4:
            raise RuntimeError(
                "Tuya 3.4 session-key negotiation failed: invalid response"
            )
        encrypted_response = response[4:]
        try:
            response_plain = self.decrypt_payload(
                self._SESSION_RESPONSE, encrypted_response
            )
        except Exception as exc:
            raise RuntimeError(
                "Tuya 3.4 session-key negotiation failed: cannot decrypt response"
            ) from exc
        if len(response_plain) < 48:
            raise RuntimeError(
                "Tuya 3.4 session-key negotiation failed: response is too short"
            )
        device_nonce, proof = response_plain[:16], response_plain[16:48]
        expected = hmac.new(self._local_key, client_nonce, hashlib.sha256).digest()
        if not hmac.compare_digest(proof, expected):
            raise RuntimeError(
                "Tuya 3.4 session-key negotiation failed: device proof mismatch"
            )
        finish_payload = self.encrypt_payload(
            self._SESSION_FINISH,
            hmac.new(self._local_key, device_nonce, hashlib.sha256).digest(),
        )
        sock.sendall(self.build_frame(next_seq, self._SESSION_FINISH, finish_payload))
        next_seq += 1
        xor_nonce = bytes(
            left ^ right for left, right in zip(client_nonce, device_nonce)
        )
        cipher = Cipher(algorithms.AES(self._local_key), modes.ECB()).encryptor()
        self.session_key = cipher.update(xor_nonce) + cipher.finalize()

        LOG.info("[status] Tuya 3.4 signaling session key negotiated")
        return next_seq
