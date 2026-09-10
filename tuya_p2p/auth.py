from __future__ import annotations

import hashlib
import struct

MAGIC = 0x12345678
AUTH_TYPE = 0
USERNAME = b"admin"
AUTH_SIZE = 104


def c_string_field(value: bytes, size: int) -> bytes:
    if size <= 0:
        raise ValueError("size must be positive")
    if len(value) >= size:
        value = value[: size - 1]
    return value + b"\x00" * (size - len(value))


def derive_credential(camera_password: str, local_key: str) -> str:
    material = f"{camera_password}||{local_key}".encode("utf-8")
    return hashlib.md5(material).hexdigest()


def build_auth_info(
    camera_password: str,
    local_key: str,
    *,
    auth_type: int = AUTH_TYPE,
    username: bytes = USERNAME,
) -> bytes:
    credential = derive_credential(camera_password, local_key).encode("ascii")

    result = (
        struct.pack("<II", MAGIC, auth_type & 0xFFFFFFFF)
        + c_string_field(username, 32)
        + c_string_field(credential, 64)
    )
    if len(result) != AUTH_SIZE:
        raise AssertionError(
            f"internal auth layout error: {len(result)} != {AUTH_SIZE}"
        )
    return result
