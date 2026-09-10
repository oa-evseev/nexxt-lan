import json

import pytest

import nexxt_lan


def write_config(tmp_path, cameras, version=1):
    path = tmp_path / "config.json"
    path.write_text(
        json.dumps(
            {
                "version": version,
                "client": {
                    "uid_env": "TEST_UID",
                    "local_ip_env": "TEST_LOCAL_IP",
                    "stun_port_env": "TEST_STUN_PORT",
                },
                "cameras": cameras,
            }
        ),
        encoding="utf-8",
    )
    return path


def camera(name, device_id, prefix, enabled=True, lan_protocol="3.3", rtc_mode=None):
    result = {
        "id": device_id,
        "name": name,
        "ip_env": f"{prefix}_IP",
        "signaling_port": 6668,
        "lan_protocol": lan_protocol,
        "local_key_env": f"{prefix}_KEY",
        "password_env": f"{prefix}_PASSWORD",
        "enabled": enabled,
    }
    if rtc_mode is not None:
        result["rtc_mode"] = rtc_mode
    return result


def set_client_env(monkeypatch):
    monkeypatch.setenv("TEST_UID", "test-client-456")
    monkeypatch.setenv("TEST_LOCAL_IP", "192.0.2.2")
    monkeypatch.setenv("TEST_STUN_PORT", "3478")


def set_camera_env(monkeypatch, prefix, ip, key, password):
    monkeypatch.setenv(f"{prefix}_IP", ip)
    monkeypatch.setenv(f"{prefix}_KEY", key)
    monkeypatch.setenv(f"{prefix}_PASSWORD", password)


def test_version_and_camera_lookup(tmp_path, monkeypatch):
    path = write_config(
        tmp_path, [camera("example-direct-camera", "test-device-123", "EXAMPLE_DIRECT")]
    )
    config = nexxt_lan.load_config(path)
    assert (
        nexxt_lan.select_camera(config, "example-direct-camera")["id"]
        == "test-device-123"
    )
    assert (
        nexxt_lan.select_camera(config, "test-device-123")["name"]
        == "example-direct-camera"
    )
    with pytest.raises(RuntimeError, match="not found"):
        nexxt_lan.select_camera(config, "missing")
    duplicate = nexxt_lan.load_config(
        write_config(
            tmp_path,
            [
                camera("same", "one", "ONE"),
                camera("same", "two", "TWO"),
            ],
        )
    )
    with pytest.raises(RuntimeError, match="ambiguous"):
        nexxt_lan.select_camera(duplicate, "same")
    with pytest.raises(RuntimeError, match="unsupported config version"):
        nexxt_lan.load_config(write_config(tmp_path, [], version=2))


def test_disabled_camera_is_rejected_before_environment_resolution(tmp_path):
    config = nexxt_lan.load_config(
        write_config(
            tmp_path,
            [camera("disabled-profile", "disabled-device", "DISABLED", enabled=False)],
        )
    )
    with pytest.raises(RuntimeError, match="disabled"):
        nexxt_lan.resolve_runtime_config(config, "disabled-profile")


def test_environment_resolution_and_validation(tmp_path, monkeypatch):
    config = nexxt_lan.load_config(
        write_config(
            tmp_path,
            [camera("example-direct-camera", "test-device-123", "EXAMPLE_DIRECT")],
        )
    )
    set_client_env(monkeypatch)
    set_camera_env(
        monkeypatch, "EXAMPLE_DIRECT", "192.0.2.3", "0123456789abcdef", "test-password"
    )
    client, selected = nexxt_lan.resolve_runtime_config(config, "example-direct-camera")
    assert client == nexxt_lan.ClientConfig("test-client-456", "192.0.2.2", 3478)
    assert selected.device_id == "test-device-123"
    assert selected.lan_protocol == "3.3"
    assert selected.rtc_mode is nexxt_lan.RTCMode.DIRECT
    monkeypatch.delenv("EXAMPLE_DIRECT_KEY")
    with pytest.raises(
        RuntimeError,
        match="EXAMPLE_DIRECT_KEY.*camera 'example-direct-camera'.*not set",
    ):
        nexxt_lan.resolve_runtime_config(config, "example-direct-camera")
    monkeypatch.setenv("EXAMPLE_DIRECT_KEY", "")
    with pytest.raises(RuntimeError, match="EXAMPLE_DIRECT_KEY"):
        nexxt_lan.resolve_runtime_config(config, "example-direct-camera")
    monkeypatch.setenv("EXAMPLE_DIRECT_KEY", "0123456789abcdef")
    monkeypatch.setenv("TEST_STUN_PORT", "70000")
    with pytest.raises(RuntimeError, match="1..65535"):
        nexxt_lan.resolve_runtime_config(config, "example-direct-camera")
    monkeypatch.setenv("TEST_STUN_PORT", "3478")
    monkeypatch.setenv("EXAMPLE_DIRECT_IP", "not-an-ip")
    with pytest.raises(RuntimeError, match="invalid network"):
        nexxt_lan.resolve_runtime_config(config, "example-direct-camera")


@pytest.mark.parametrize("lan_protocol", ["3.3", "3.4"])
def test_lan_protocol_is_resolved_from_camera_config(
    tmp_path, monkeypatch, lan_protocol
):
    config = nexxt_lan.load_config(
        write_config(
            tmp_path,
            [
                camera(
                    "example-preconnect-camera",
                    "device",
                    "EXAMPLE_PRECONNECT",
                    lan_protocol=lan_protocol,
                )
            ],
        )
    )
    set_client_env(monkeypatch)
    set_camera_env(
        monkeypatch, "EXAMPLE_PRECONNECT", "192.0.2.3", "0123456789abcdef", "password"
    )
    _client, selected = nexxt_lan.resolve_runtime_config(
        config, "example-preconnect-camera"
    )
    assert selected.lan_protocol == lan_protocol


@pytest.mark.parametrize("rtc_mode", ["direct", "preconnect"])
def test_explicit_rtc_mode_is_resolved_from_camera_config(
    tmp_path,
    monkeypatch,
    rtc_mode,
):
    config = nexxt_lan.load_config(
        write_config(
            tmp_path,
            [
                camera(
                    "example-preconnect-camera",
                    "device",
                    "EXAMPLE_PRECONNECT",
                    lan_protocol="3.4",
                    rtc_mode=rtc_mode,
                )
            ],
        )
    )
    set_client_env(monkeypatch)
    set_camera_env(
        monkeypatch, "EXAMPLE_PRECONNECT", "192.0.2.3", "0123456789abcdef", "password"
    )

    _client, selected = nexxt_lan.resolve_runtime_config(
        config, "example-preconnect-camera"
    )

    assert selected.rtc_mode is nexxt_lan.RTCMode(rtc_mode)


def test_missing_rtc_mode_defaults_to_direct_and_cli_override_wins(
    tmp_path, monkeypatch
):
    config = nexxt_lan.load_config(
        write_config(
            tmp_path,
            [
                camera(
                    "example-preconnect-camera",
                    "device",
                    "EXAMPLE_PRECONNECT",
                    lan_protocol="3.4",
                )
            ],
        )
    )
    set_client_env(monkeypatch)
    set_camera_env(
        monkeypatch, "EXAMPLE_PRECONNECT", "192.0.2.3", "0123456789abcdef", "password"
    )
    _client, selected = nexxt_lan.resolve_runtime_config(
        config, "example-preconnect-camera"
    )

    assert selected.rtc_mode is nexxt_lan.RTCMode.DIRECT
    assert (
        nexxt_lan.resolve_rtc_mode(selected, "preconnect")
        is nexxt_lan.RTCMode.PRECONNECT
    )


def test_cli_rtc_mode_override_wins_over_profile(tmp_path, monkeypatch):
    config = nexxt_lan.load_config(
        write_config(
            tmp_path,
            [
                camera(
                    "example-preconnect-camera",
                    "device",
                    "EXAMPLE_PRECONNECT",
                    lan_protocol="3.4",
                    rtc_mode="preconnect",
                )
            ],
        )
    )
    set_client_env(monkeypatch)
    set_camera_env(
        monkeypatch, "EXAMPLE_PRECONNECT", "192.0.2.3", "0123456789abcdef", "password"
    )
    _client, selected = nexxt_lan.resolve_runtime_config(
        config, "example-preconnect-camera"
    )

    assert nexxt_lan.resolve_rtc_mode(selected, "direct") is nexxt_lan.RTCMode.DIRECT


def test_preconnect_profile_requires_lan_34(tmp_path, monkeypatch):
    config = nexxt_lan.load_config(
        write_config(
            tmp_path,
            [
                camera(
                    "camera",
                    "device",
                    "CAMERA",
                    lan_protocol="3.3",
                    rtc_mode="preconnect",
                )
            ],
        )
    )
    set_client_env(monkeypatch)
    set_camera_env(monkeypatch, "CAMERA", "192.0.2.3", "0123456789abcdef", "password")

    with pytest.raises(RuntimeError, match="rtc_mode 'preconnect'.*lan_protocol '3.4'"):
        nexxt_lan.resolve_runtime_config(config, "camera")


def test_invalid_lan_protocol_is_rejected(tmp_path, monkeypatch):
    config = nexxt_lan.load_config(
        write_config(
            tmp_path,
            [
                camera(
                    "example-preconnect-camera",
                    "device",
                    "EXAMPLE_PRECONNECT",
                    lan_protocol="9.9",
                )
            ],
        )
    )
    set_client_env(monkeypatch)
    set_camera_env(
        monkeypatch, "EXAMPLE_PRECONNECT", "192.0.2.3", "0123456789abcdef", "password"
    )
    with pytest.raises(RuntimeError, match="unsupported lan_protocol '9.9'.*3.3, 3.4"):
        nexxt_lan.resolve_runtime_config(config, "example-preconnect-camera")


def test_selected_profile_is_isolated_in_all_generated_messages(tmp_path, monkeypatch):
    config = nexxt_lan.load_config(
        write_config(
            tmp_path,
            [
                camera(
                    "example-direct-camera",
                    "example-direct-camera-device",
                    "EXAMPLE_DIRECT",
                ),
                camera("selected-profile", "selected-device", "SELECTED"),
            ],
        )
    )
    set_client_env(monkeypatch)
    set_camera_env(
        monkeypatch,
        "EXAMPLE_DIRECT",
        "192.0.2.3",
        "example-direct-camera-key-0001",
        "example-direct-camera-password",
    )
    set_camera_env(
        monkeypatch,
        "SELECTED",
        "192.0.2.25",
        "selected-key-0001",
        "selected-password",
    )
    client, selected = nexxt_lan.resolve_runtime_config(config, "selected-profile")
    session_id = nexxt_lan.generate_session_id(selected.device_id)
    trace_id = nexxt_lan.build_trace_id(
        base_trace_id="trace", dev_id=selected.device_id
    )
    offer = nexxt_lan.build_offer(
        client,
        selected,
        session_id=session_id,
        trace_id=trace_id,
        ice_credentials=("ufrg", "p" * 24),
        aes_key=b"x" * 16,
    )
    candidate = nexxt_lan.make_candidate_message(
        client_id=client.uid,
        device_id=selected.device_id,
        session_id=session_id,
        trace_id=trace_id,
        local_ip=client.local_ip,
        local_port=50000,
    )
    session = nexxt_lan.PreparedSession(
        b"selected-key-0001",
        offer,
        session_id,
        trace_id,
        client.uid,
        "p" * 24,
        "ufrg",
        b"x" * 16,
        b"a" * 104,
        selected,
    )
    disconnect = nexxt_lan.build_disconnect_message(session)
    assert (
        offer["header"]["to"]
        == candidate["header"]["to"]
        == disconnect["header"]["to"]
        == "selected-device"
    )
    assert offer["header"]["from"] == client.uid
    assert f"cname:{client.uid}" in offer["msg"]["sdp"]
    assert session_id.startswith(selected.device_id)
    assert selected.device_id in trace_id
    assert offer["msg"]["token"] == [{"urls": "stun:192.0.2.2:3478"}]

    targets = []

    class FakeSocket:
        def settimeout(self, _timeout):
            pass

    monkeypatch.setattr(
        nexxt_lan.socket,
        "create_connection",
        lambda target, timeout: targets.append((target, timeout)) or FakeSocket(),
    )
    nexxt_lan.open_signaling_connection(selected)
    assert targets == [(("192.0.2.25", 6668), 5)]
