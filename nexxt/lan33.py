"""Self-contained Tuya LAN 3.3 framing and payload cryptography."""

import json
import socket
import struct
import zlib

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

PREFIX = 0x000055AA
SUFFIX = 0x0000AA55


def pkcs7_pad(data: bytes) -> bytes:
    n = 16 - (len(data) % 16)
    return data + bytes([n]) * n


def pkcs7_unpad(data: bytes) -> bytes:
    if not data:
        return data
    n = data[-1]
    if not 1 <= n <= 16:
        return data
    if data[-n:] != bytes([n]) * n:
        return data
    return data[:-n]


def aes_encrypt(data: bytes, key: bytes) -> bytes:
    enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    padded = pkcs7_pad(data)
    return enc.update(padded) + enc.finalize()


def aes_decrypt(data: bytes, key: bytes) -> bytes:
    dec = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
    plain = dec.update(data) + dec.finalize()
    return pkcs7_unpad(plain)


def build_frame(seq: int, cmd: int, payload: bytes) -> bytes:
    # Tuya 55AA:
    # prefix | seq | cmd | length | payload | crc32 | suffix
    #
    # length includes payload + CRC + suffix = payload + 8 bytes.
    header = struct.pack(
        ">IIII",
        PREFIX,
        seq,
        cmd,
        len(payload) + 8,
    )

    body = header + payload
    crc = zlib.crc32(body) & 0xFFFFFFFF

    return body + struct.pack(">II", crc, SUFFIX)


def recv_exact(sock: socket.socket, n: int) -> bytes:
    out = bytearray()
    while len(out) < n:
        chunk = sock.recv(n - len(out))
        if not chunk:
            raise EOFError("connection closed")
        out.extend(chunk)
    return bytes(out)


def recv_frame(sock: socket.socket) -> tuple[int, int, bytes]:
    header = recv_exact(sock, 16)

    prefix, seq, cmd, length = struct.unpack(">IIII", header)

    if prefix != PREFIX:
        raise ValueError(f"bad prefix: 0x{prefix:08x}")

    rest = recv_exact(sock, length)

    payload = rest[:-8]
    recv_crc, suffix = struct.unpack(">II", rest[-8:])

    if suffix != SUFFIX:
        raise ValueError(f"bad suffix: 0x{suffix:08x}")

    calc_crc = zlib.crc32(header + payload) & 0xFFFFFFFF

    if recv_crc != calc_crc:
        raise ValueError(
            f"bad CRC: received=0x{recv_crc:08x} calculated=0x{calc_crc:08x}"
        )

    return seq, cmd, payload


def decode_camera_payload(payload: bytes, key: bytes) -> dict | None:
    # Camera -> client cmd 0x20 application payload:
    #
    #   retcode uint32
    #   AES(localKey, JSON)
    #
    if len(payload) < 4:
        return None

    retcode = struct.unpack(">I", payload[:4])[0]
    ciphertext = payload[4:]

    if not ciphertext or len(ciphertext) % 16:
        return {
            "retcode": retcode,
            "raw": ciphertext.hex(),
        }

    try:
        plain = aes_decrypt(ciphertext, key)
        obj = json.loads(plain.decode())
        return {
            "retcode": retcode,
            "json": obj,
        }
    except Exception as exc:
        return {
            "retcode": retcode,
            "decode_error": str(exc),
            "raw_prefix": ciphertext[:64].hex(),
        }
