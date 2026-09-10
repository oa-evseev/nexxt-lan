import json

import pytest

from nexxt.config import (
    EnvironmentDeviceResolver,
    assemble_camera_config,
    load_config,
    resolve_device_credentials,
    resolve_device_runtime,
    resolve_runtime_config,
    select_camera,
)
from nexxt.device import DeviceConfig, DeviceRuntime, RTCMode


def write_config(tmp_path, camera):
    path = tmp_path / "config.json"
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "client": {
                    "uid_env": "TEST_UID",
                    "local_ip_env": "TEST_LOCAL_IP",
                    "stun_port_env": "TEST_STUN_PORT",
                },
                "cameras": [camera],
            }
        ),
        encoding="utf-8",
    )
    return path


def profile(*, lan_protocol="3.3", rtc_mode=None, enabled=True):
    camera = {
        "id": "device-123",
        "name": "camera",
        "ip_env": "CAMERA_IP",
        "local_key_env": "CAMERA_KEY",
        "password_env": "CAMERA_PASSWORD",
        "signaling_port": 6668,
        "lan_protocol": lan_protocol,
        "enabled": enabled,
    }
    if rtc_mode is not None:
        camera["rtc_mode"] = rtc_mode
    return camera


def set_env(monkeypatch):
    monkeypatch.setenv("TEST_UID", "client")
    monkeypatch.setenv("TEST_LOCAL_IP", "192.0.2.2")
    monkeypatch.setenv("TEST_STUN_PORT", "3478")
    monkeypatch.setenv("CAMERA_IP", "192.0.2.3")
    monkeypatch.setenv("CAMERA_KEY", "0123456789abcdef")
    monkeypatch.setenv("CAMERA_PASSWORD", "password")


def test_profile_is_stable_and_runtime_holds_legacy_ip_resolution(
    tmp_path, monkeypatch
):
    config = load_config(write_config(tmp_path, profile()))
    device = select_camera(config, "camera")

    assert isinstance(device, DeviceConfig)
    assert device.id == "device-123"
    assert device.ip_env == "CAMERA_IP"
    assert not hasattr(device, "ip")

    set_env(monkeypatch)
    runtime = resolve_device_runtime(device)
    assert runtime == DeviceRuntime(device_id="device-123", ip="192.0.2.3")


@pytest.mark.parametrize(
    ("lan_protocol", "rtc_mode"),
    [("3.3", "direct"), ("3.4", "preconnect")],
)
def test_legacy_env_resolution_keeps_protocol_and_rtc_mode_separate(
    tmp_path,
    monkeypatch,
    lan_protocol,
    rtc_mode,
):
    config = load_config(
        write_config(
            tmp_path,
            profile(
                lan_protocol=lan_protocol,
                rtc_mode=rtc_mode,
            ),
        )
    )
    set_env(monkeypatch)

    _client, camera = resolve_runtime_config(config, "camera")

    assert camera.ip == "192.0.2.3"
    assert camera.lan_protocol == lan_protocol
    assert camera.rtc_mode is RTCMode(rtc_mode)


def test_default_direct_and_disabled_or_missing_legacy_env_errors(
    tmp_path, monkeypatch
):
    config = load_config(write_config(tmp_path, profile()))
    set_env(monkeypatch)
    _client, camera = resolve_runtime_config(config, "camera")
    assert camera.rtc_mode is RTCMode.DIRECT

    monkeypatch.delenv("CAMERA_IP")
    with pytest.raises(RuntimeError, match="CAMERA_IP.*not set"):
        resolve_device_runtime(select_camera(config, "camera"))

    disabled = load_config(write_config(tmp_path, profile(enabled=False)))
    with pytest.raises(RuntimeError, match="disabled"):
        select_camera(disabled, "camera")
    with pytest.raises(RuntimeError, match="not found"):
        select_camera(config, "unknown")


def test_environment_device_resolver_returns_the_legacy_runtime_ip(
    tmp_path, monkeypatch
):
    config = load_config(write_config(tmp_path, profile()))
    monkeypatch.setenv("CAMERA_IP", "192.0.2.42")

    runtime = EnvironmentDeviceResolver().resolve(select_camera(config, "camera"))

    assert runtime == DeviceRuntime(device_id="device-123", ip="192.0.2.42")


def test_injectable_resolver_changes_runtime_ip_but_not_device_profile(
    tmp_path, monkeypatch
):
    config = load_config(
        write_config(tmp_path, profile(lan_protocol="3.4", rtc_mode="preconnect"))
    )
    profile_before = select_camera(config, "camera")
    set_env(monkeypatch)

    class FakeResolver:
        def resolve(self, device):
            assert device is profile_before
            return DeviceRuntime(device_id=device.id, ip="192.0.2.99")

    _client, camera = resolve_runtime_config(config, "camera", resolver=FakeResolver())

    assert camera.ip == "192.0.2.99"
    assert select_camera(config, "camera") is profile_before
    assert profile_before.ip_env == "CAMERA_IP"
    assert camera.lan_protocol == "3.4"
    assert camera.rtc_mode is RTCMode.PRECONNECT


def test_credentials_are_resolved_outside_the_device_resolver_and_assemble_legacy_view(
    tmp_path,
    monkeypatch,
):
    config = load_config(
        write_config(tmp_path, profile(lan_protocol="3.4", rtc_mode="preconnect"))
    )
    device = select_camera(config, "camera")
    set_env(monkeypatch)

    class RuntimeOnlyResolver:
        def resolve(self, received):
            assert received is device
            return DeviceRuntime(device_id=received.id, ip="192.0.2.88")

    runtime = resolve_device_runtime(device, RuntimeOnlyResolver())
    credentials = resolve_device_credentials(device)
    camera = assemble_camera_config(device, runtime, credentials)

    assert credentials.local_key == "0123456789abcdef"
    assert credentials.password == "password"
    assert camera.device_id == "device-123"
    assert camera.ip == "192.0.2.88"
    assert camera.local_key == "0123456789abcdef"
    assert camera.password == "password"
    assert camera.lan_protocol == "3.4"
    assert camera.rtc_mode is RTCMode.PRECONNECT
