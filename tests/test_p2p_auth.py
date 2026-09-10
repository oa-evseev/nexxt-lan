import struct

import pytest

from tuya_p2p.auth import (
    AUTH_SIZE,
    MAGIC,
    build_auth_info,
    c_string_field,
    derive_credential,
)


def test_auth_layout():
    blob = build_auth_info("pw", "local")
    assert len(blob) == AUTH_SIZE
    assert blob[:4] == MAGIC.to_bytes(4, "little")
    assert blob[4:8] == b"\x00\x00\x00\x00"
    assert blob[8:13] == b"admin"
    assert blob[13:40] == b"\x00" * 27

    cred = derive_credential("pw", "local").encode("ascii")
    assert blob[40:72] == cred
    assert blob[72:] == b"\x00" * 32


def test_credential_matches_known_protocol_vector():
    assert derive_credential("pw", "local") == "9792e8987fbe982866a24741ddd54e47"


def test_auth_fields_are_nul_terminated_and_do_not_overflow():
    blob = build_auth_info(
        "password",
        "local-key",
        auth_type=0x1_0000_0002,
        username=b"u" * 40,
    )

    magic, auth_type = struct.unpack_from("<II", blob)
    username = blob[8:40]
    credential = blob[40:104]

    assert (magic, auth_type) == (MAGIC, 2)
    assert username == b"u" * 31 + b"\x00"
    assert credential[32:] == b"\x00" * 32


@pytest.mark.parametrize(
    ("value", "size", "expected"),
    [
        (b"", 1, b"\x00"),
        (b"ab", 4, b"ab\x00\x00"),
        (b"abcd", 4, b"abc\x00"),
    ],
)
def test_c_string_field_follows_fixed_width_c_semantics(value, size, expected):
    assert c_string_field(value, size) == expected


def test_c_string_field_rejects_non_positive_width():
    with pytest.raises(ValueError, match="positive"):
        c_string_field(b"value", 0)
