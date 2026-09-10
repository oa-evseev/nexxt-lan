import sys
from types import SimpleNamespace

import pytest

from nexxt.device import DeviceConfig, DeviceRuntime
from nexxt.device_resolver import (
    EnvironmentDeviceResolver,
    EnvironmentThenDiscoveryResolver,
    TinyTuyaDeviceResolver,
)


def device(*, lan_protocol="3.3"):
    return DeviceConfig(
        id="wanted-id",
        name="camera",
        lan_protocol=lan_protocol,
        rtc_mode="direct",
        signaling_port=6668,
        enabled=True,
        ip_env="CAMERA_IP",
        local_key_env="CAMERA_KEY",
        password_env="CAMERA_PASSWORD",
    )


def test_tinytuya_resolver_selects_only_configured_device_id_and_returns_ip():
    scans = []

    def scan():
        scans.append(True)
        return {
            "192.0.2.7": {"gwId": "other-id", "version": "3.4"},
            "192.0.2.8": {"gwId": "wanted-id", "version": "3.3"},
        }

    runtime = TinyTuyaDeviceResolver(scan=scan).resolve(device())

    assert scans == [True]
    assert runtime == DeviceRuntime(device_id="wanted-id", ip="192.0.2.8")
    assert type(runtime.ip) is str
    assert not hasattr(runtime, "gwId")
    assert not hasattr(runtime, "version")


def test_tinytuya_resolver_ignores_other_devices_and_errors_when_target_absent():
    resolver = TinyTuyaDeviceResolver(
        scan=lambda: {"192.0.2.7": {"gwId": "other-id", "version": "3.3"}},
    )

    with pytest.raises(
        RuntimeError, match="did not find configured device ID 'wanted-id'"
    ):
        resolver.resolve(device())


def test_tinytuya_network_call_uses_public_non_polling_discovery_api(monkeypatch):
    calls = []

    def device_scan(**kwargs):
        calls.append(kwargs)
        return {"192.0.2.8": {"gwId": "wanted-id"}}

    monkeypatch.setitem(
        sys.modules, "tinytuya", SimpleNamespace(deviceScan=device_scan)
    )

    runtime = TinyTuyaDeviceResolver().resolve(device())

    assert runtime.ip == "192.0.2.8"
    assert calls == [
        {"verbose": False, "color": False, "poll": False, "forcescan": False}
    ]


def test_reported_protocol_warns_but_never_changes_configured_protocol():
    profile = device(lan_protocol="3.3")
    resolver = TinyTuyaDeviceResolver(
        scan=lambda: {"192.0.2.8": {"gwId": "wanted-id", "version": "3.4"}},
    )

    with pytest.warns(RuntimeWarning, match="configured lan_protocol remains '3.3'"):
        runtime = resolver.resolve(profile)

    assert runtime.ip == "192.0.2.8"
    assert profile.lan_protocol == "3.3"


def test_discovery_resolver_neither_reads_nor_receives_credentials(monkeypatch):
    monkeypatch.setenv("CAMERA_KEY", "must-not-be-read")
    monkeypatch.setenv("CAMERA_PASSWORD", "must-not-be-read")
    seen = []

    def scan():
        seen.append(True)
        return {"192.0.2.8": {"gwId": "wanted-id"}}

    runtime = TinyTuyaDeviceResolver(scan=scan).resolve(device())

    assert seen == [True]
    assert runtime == DeviceRuntime(device_id="wanted-id", ip="192.0.2.8")


def test_legacy_environment_resolver_remains_working(monkeypatch):
    monkeypatch.setenv("CAMERA_IP", "192.0.2.42")

    assert EnvironmentDeviceResolver().resolve(device()) == DeviceRuntime(
        device_id="wanted-id",
        ip="192.0.2.42",
    )


def test_fallback_does_not_discover_when_legacy_ip_hint_is_valid(monkeypatch):
    monkeypatch.setenv("CAMERA_IP", "192.0.2.42")
    calls = []

    class Discovery:
        def resolve(self, profile):
            calls.append(profile)
            return DeviceRuntime(device_id=profile.id, ip="192.0.2.8")

    runtime = EnvironmentThenDiscoveryResolver(discovery=Discovery()).resolve(device())

    assert runtime.ip == "192.0.2.42"
    assert calls == []


@pytest.mark.parametrize("hint", [None, "not-an-ip"])
def test_fallback_discovers_when_legacy_ip_hint_is_absent_or_invalid(monkeypatch, hint):
    if hint is None:
        monkeypatch.delenv("CAMERA_IP", raising=False)
    else:
        monkeypatch.setenv("CAMERA_IP", hint)
    calls = []

    class Discovery:
        def resolve(self, profile):
            calls.append(profile.id)
            return DeviceRuntime(device_id=profile.id, ip="192.0.2.8")

    runtime = EnvironmentThenDiscoveryResolver(discovery=Discovery()).resolve(device())

    assert runtime == DeviceRuntime(device_id="wanted-id", ip="192.0.2.8")
    assert calls == ["wanted-id"]
