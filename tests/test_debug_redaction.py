import logging

import nexxt_lan

SESSION_TOKEN = "synthetic-device1700000000AbCd1234"
ICE_PASSWORD = "AbCdEfGhIjKlMnOpQrStUvWx"
AES_KEY = "00112233445566778899aabbccddeeff"
CNAME = "synthetic-cname-example"
CLI_BASE = ["--config", "synthetic-config.json", "--camera", "test"]


def sample_offer() -> dict:
    return {
        "msg": {
            "preconnect": True,
            "sdp": (
                "v=0\r\n"
                f"a=msid-semantic: WMS {SESSION_TOKEN}\r\n"
                "a=ice-ufrag:Ab3X\r\n"
                f"a=ice-pwd:{ICE_PASSWORD}\r\n"
                f"a=aes-key:{AES_KEY}\r\n"
                f"a=ssrc:0 cname:{CNAME}\r\n"
            ),
        }
    }


def test_redacts_chunks_inside_json_values_without_changing_structure():
    token_as_key = SESSION_TOKEN
    source = sample_offer()
    source[token_as_key] = f"prefix:{SESSION_TOKEN}:suffix"

    redacted = nexxt_lan.redact_high_entropy_json_values(source)

    assert token_as_key in redacted
    assert redacted["msg"]["preconnect"] is True
    assert "a=msid-semantic: WMS <redacted>" in redacted["msg"]["sdp"]
    assert "a=ice-ufrag:<redacted>" in redacted["msg"]["sdp"]
    assert "a=ice-pwd:<redacted>" in redacted["msg"]["sdp"]
    assert "a=aes-key:<redacted>" in redacted["msg"]["sdp"]
    assert "cname:<redacted>" in redacted["msg"]["sdp"]
    assert redacted[token_as_key] == "prefix:<redacted>:suffix"
    assert SESSION_TOKEN in source["msg"]["sdp"]


def test_safe_debug_redacts_and_unsafe_debug_preserves_token():
    record = logging.LogRecord(
        name="test",
        level=logging.DEBUG,
        pathname=__file__,
        lineno=1,
        msg="session=%s",
        args=(SESSION_TOKEN,),
        exc_info=None,
    )

    safe_output = nexxt_lan.DebugFormatter(unsafe_debug=False).format(record)
    unsafe_output = nexxt_lan.DebugFormatter(unsafe_debug=True).format(record)

    assert safe_output == "session=<redacted>"
    assert unsafe_output == f"session={SESSION_TOKEN}"


def test_cli_debug_modes_are_mutually_exclusive():
    assert nexxt_lan.parse_args([*CLI_BASE, "--debug"]).debug is True
    assert nexxt_lan.parse_args([*CLI_BASE, "--debug-unsafe"]).debug_unsafe is True


def test_preconnect_activate_delay_cli_defaults_to_zero_and_accepts_milliseconds():
    assert nexxt_lan.parse_args(CLI_BASE).preconnect_activate_delay_ms == 0
    assert (
        nexxt_lan.parse_args(
            [*CLI_BASE, "--preconnect-activate-delay-ms", "25"]
        ).preconnect_activate_delay_ms
        == 25
    )


def test_safe_json_keeps_sdp_readable():
    output = nexxt_lan.json_for_debug(sample_offer(), unsafe_debug=False)

    assert '"preconnect": true' in output
    assert "a=ice-pwd:<redacted>" in output
    assert ICE_PASSWORD not in output


def test_unsafe_json_preserves_original_values():
    output = nexxt_lan.json_for_debug(sample_offer(), unsafe_debug=True)

    assert SESSION_TOKEN in output
    assert "a=ice-ufrag:Ab3X" in output
    assert ICE_PASSWORD in output
    assert AES_KEY in output
    assert CNAME in output
