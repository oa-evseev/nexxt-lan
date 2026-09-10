"""Stable device profiles and per-attempt device state."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class RTCMode(str, Enum):
    """RTC startup variants supported by the device protocol."""

    DIRECT = "direct"
    PRECONNECT = "preconnect"


@dataclass(frozen=True, slots=True)
class DeviceConfig:
    """Persistent device profile; network addresses are runtime state."""

    id: str
    name: str
    lan_protocol: str
    rtc_mode: str
    signaling_port: int
    enabled: bool
    ip_env: str
    local_key_env: str
    password_env: str

    # ``select_camera`` historically returned a JSON object.  Retain the
    # small mapping surface used by programmatic callers during this step.
    def __getitem__(self, key: str) -> object:
        return getattr(self, key)

    def get(self, key: str, default: object = None) -> object:
        return getattr(self, key, default)


@dataclass(frozen=True, slots=True)
class DeviceRuntime:
    """Current resolved or discovered LAN location for a device."""

    device_id: str
    ip: str

    @property
    def id(self) -> str:
        """Alias used by discovery implementations that report ``id``."""
        return self.device_id


@dataclass(frozen=True, slots=True)
class DeviceCredentials:
    """Secrets resolved locally for one device connection attempt."""

    local_key: str
    password: str


@dataclass(frozen=True, slots=True)
class ClientConfig:
    """Resolved client network settings for one connection attempt."""

    uid: str
    local_ip: str
    stun_port: int


@dataclass(frozen=True, slots=True)
class CameraConfig:
    """Legacy streaming view combining a profile and its runtime location.

    Kept while signaling and media code still consume this shape directly.
    New configuration and discovery code should use ``DeviceConfig`` and
    ``DeviceRuntime`` respectively.
    """

    name: str
    device_id: str
    ip: str
    signaling_port: int
    local_key: str
    password: str
    lan_protocol: str = "3.3"
    rtc_mode: RTCMode = RTCMode.DIRECT
