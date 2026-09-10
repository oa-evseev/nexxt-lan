"""Version 1 config parsing and legacy environment-based runtime resolution."""

from __future__ import annotations

import ipaddress
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .device import (
    CameraConfig,
    ClientConfig,
    DeviceConfig,
    DeviceCredentials,
    DeviceRuntime,
    RTCMode,
)
from .device_resolver import DeviceResolver, EnvironmentDeviceResolver


@dataclass(frozen=True, slots=True)
class ConfigFile:
    client_env: dict[str, str]
    cameras: tuple[DeviceConfig, ...]


def _required_string(value: object, description: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise RuntimeError(f"{description} is required")
    return value.strip()


def _environment_value(env_name: str, description: str) -> str:
    value = os.environ.get(env_name)
    if value is None or not value.strip():
        raise RuntimeError(
            f"environment variable {env_name} required for {description} is not set"
        )
    return value.strip()


def _device_config(raw: dict[str, object]) -> DeviceConfig:
    name = _required_string(raw.get("name"), "config camera.name")
    rtsp_enabled = raw.get("rtsp", False)
    if not isinstance(rtsp_enabled, bool):
        raise RuntimeError(f"config camera {name!r}.rtsp must be a boolean")
    rtsp_path = (
        _required_string(raw["rtsp_path"], f"config camera {name!r}.rtsp_path")
        if "rtsp_path" in raw and raw["rtsp_path"] is not None
        else (name if rtsp_enabled else None)
    )
    return DeviceConfig(
        id=_required_string(raw.get("id"), f"config camera {name!r}.id"),
        name=name,
        lan_protocol=_required_string(
            raw.get("lan_protocol"), f"config camera {name!r}.lan_protocol"
        ),
        rtc_mode=raw.get("rtc_mode", RTCMode.DIRECT.value),
        signaling_port=raw.get("signaling_port"),
        enabled=raw.get("enabled"),
        ip_env=_required_string(raw.get("ip_env"), f"config camera {name!r}.ip_env"),
        local_key_env=_required_string(
            raw.get("local_key_env"), f"config camera {name!r}.local_key_env"
        ),
        password_env=_required_string(
            raw.get("password_env"), f"config camera {name!r}.password_env"
        ),
        rtsp_path=rtsp_path,
    )


def load_config(path: Path) -> ConfigFile:
    """Read and minimally validate the versioned production config contract."""
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"cannot read config {path}: {exc}") from exc
    if not isinstance(raw, dict) or raw.get("version") != 1:
        raise RuntimeError("unsupported config version (expected 1)")
    client = raw.get("client")
    cameras = raw.get("cameras")
    if not isinstance(client, dict) or not isinstance(cameras, list):
        raise RuntimeError("config requires client object and cameras array")
    client_env = {
        key: _required_string(client.get(key), f"config client.{key}")
        for key in ("uid_env", "local_ip_env", "stun_port_env")
    }
    if not all(isinstance(camera, dict) for camera in cameras):
        raise RuntimeError("config cameras must contain objects")
    return ConfigFile(
        client_env=client_env,
        cameras=tuple(_device_config(camera) for camera in cameras),
    )


def select_camera(config: ConfigFile, selector: str) -> DeviceConfig:
    """Select by canonical name, with device-id selection as a convenience."""
    matches = [camera for camera in config.cameras if camera.name == selector]
    if not matches:
        matches = [camera for camera in config.cameras if camera.id == selector]
    if not matches:
        raise RuntimeError(f"camera {selector!r} not found in config")
    if len(matches) != 1:
        raise RuntimeError(f"camera selector {selector!r} is ambiguous")
    camera = matches[0]
    if camera.enabled is not True:
        raise RuntimeError(f"camera {selector!r} is disabled")
    return camera


def select_serve_cameras(
    config: ConfigFile, selectors: tuple[str, ...] | list[str] = ()
) -> tuple[DeviceConfig, ...]:
    """Return RTSP-enabled profiles, optionally restricted by camera name.

    With no filter, every explicitly RTSP-enabled profile is selected. A
    profile remains opt-in: ``rtsp_path`` is required even when a CLI filter
    is supplied.
    """
    requested = tuple(selectors)
    if requested:
        selected = tuple(select_camera(config, selector) for selector in requested)
        names = [camera.name for camera in selected]
        if len(set(names)) != len(names):
            raise RuntimeError("a camera was selected more than once")
    else:
        selected = tuple(
            camera
            for camera in config.cameras
            if camera.enabled is True and camera.rtsp_path is not None
        )
    missing = [camera.name for camera in selected if camera.rtsp_path is None]
    if missing:
        raise RuntimeError(
            "camera(s) are not enabled for serve (missing rtsp_path): "
            + ", ".join(missing)
        )
    if not selected:
        raise RuntimeError("no RTSP-enabled cameras selected (set camera.rtsp_path)")
    return selected


def resolve_rtc_mode(
    camera: CameraConfig, cli_override: Optional[str] = None
) -> RTCMode:
    """Resolve one device's RTC startup mode, with an optional CLI override."""
    raw_mode = cli_override if cli_override is not None else camera.rtc_mode
    try:
        mode = raw_mode if isinstance(raw_mode, RTCMode) else RTCMode(raw_mode)
    except (TypeError, ValueError) as exc:
        raise RuntimeError(
            f"unsupported rtc_mode {raw_mode!r} for camera {camera.name!r} "
            "(supported: direct, preconnect)"
        ) from exc
    if mode is RTCMode.PRECONNECT and camera.lan_protocol != "3.4":
        raise RuntimeError(
            f"rtc_mode 'preconnect' for camera {camera.name!r} requires "
            "lan_protocol '3.4'"
        )
    return mode


def resolve_device_runtime(
    camera: DeviceConfig,
    resolver: DeviceResolver | None = None,
) -> DeviceRuntime:
    """Resolve per-attempt device network state through an injectable boundary.

    Omitting ``resolver`` preserves the legacy ``ip_env`` behavior.
    """
    return (resolver or EnvironmentDeviceResolver()).resolve(camera)


def resolve_device_credentials(camera: DeviceConfig) -> DeviceCredentials:
    """Resolve local secrets independently of runtime device location."""
    return DeviceCredentials(
        local_key=_environment_value(camera.local_key_env, f"camera {camera.name!r}"),
        password=_environment_value(camera.password_env, f"camera {camera.name!r}"),
    )


def resolve_client_config(config: ConfigFile) -> ClientConfig:
    """Resolve validated client-wide environment settings for one attempt."""
    uid = _environment_value(config.client_env["uid_env"], "client")
    local_ip = _environment_value(config.client_env["local_ip_env"], "client")
    stun_text = _environment_value(config.client_env["stun_port_env"], "client")
    try:
        ipaddress.ip_address(local_ip)
        stun_port = int(stun_text)
    except ValueError as exc:
        raise RuntimeError(f"invalid client network configuration: {exc}") from exc
    if not 1 <= stun_port <= 65535:
        raise RuntimeError("client STUN port must be in range 1..65535")
    return ClientConfig(uid=uid, local_ip=local_ip, stun_port=stun_port)


def assemble_camera_config(
    profile: DeviceConfig,
    runtime: DeviceRuntime,
    credentials: DeviceCredentials,
) -> CameraConfig:
    """Build the legacy streaming view from independent resolved inputs."""
    if profile.lan_protocol not in {"3.3", "3.4"}:
        raise RuntimeError(
            f"unsupported lan_protocol {profile.lan_protocol!r} for camera {profile.name!r} "
            "(supported: 3.3, 3.4)"
        )
    if not isinstance(profile.rtc_mode, str):
        raise RuntimeError(f"config camera {profile.name!r}.rtc_mode must be a string")
    try:
        signaling_port = int(profile.signaling_port)
    except (ValueError, TypeError) as exc:
        raise RuntimeError(
            f"invalid network configuration for camera {profile.name!r}: {exc}"
        ) from exc
    if not 1 <= signaling_port <= 65535:
        raise RuntimeError(
            f"signaling port for camera {profile.name!r} must be in range 1..65535"
        )
    camera = CameraConfig(
        name=profile.name,
        device_id=runtime.device_id,
        ip=runtime.ip,
        signaling_port=signaling_port,
        local_key=credentials.local_key,
        password=credentials.password,
        lan_protocol=profile.lan_protocol,
        rtc_mode=profile.rtc_mode,
    )
    return CameraConfig(
        name=camera.name,
        device_id=camera.device_id,
        ip=camera.ip,
        signaling_port=camera.signaling_port,
        local_key=camera.local_key,
        password=camera.password,
        lan_protocol=camera.lan_protocol,
        rtc_mode=resolve_rtc_mode(camera),
    )


def resolve_runtime_config(
    config: ConfigFile,
    selector: str,
    resolver: DeviceResolver | None = None,
) -> tuple[ClientConfig, CameraConfig]:
    """Resolve config into legacy streaming inputs for one attempt.

    ``resolver`` controls only runtime device information; credentials remain
    local configuration concerns.
    """
    profile = select_camera(config, selector)
    client = resolve_client_config(config)
    runtime = resolve_device_runtime(profile, resolver)
    credentials = resolve_device_credentials(profile)
    return client, assemble_camera_config(profile, runtime, credentials)
