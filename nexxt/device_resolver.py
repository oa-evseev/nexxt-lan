"""Runtime device-location resolution boundaries.

Resolvers provide ephemeral network information only.  Device credentials are
intentionally resolved by the configuration layer, not by discovery.
"""

from __future__ import annotations

import ipaddress
import os
import warnings
from collections.abc import Callable, Mapping
from typing import Protocol

from .device import DeviceConfig, DeviceRuntime


class DeviceResolver(Protocol):
    """Resolve one stable device profile to its current runtime location."""

    def resolve(self, device: DeviceConfig) -> DeviceRuntime:
        """Return runtime network information for ``device``."""


class EnvironmentDeviceResolver:
    """Resolve the legacy ``ip_env`` setting for a connection attempt."""

    def resolve(self, device: DeviceConfig) -> DeviceRuntime:
        value = os.environ.get(device.ip_env)
        if value is None or not value.strip():
            raise RuntimeError(
                f"environment variable {device.ip_env} required for "
                f"camera {device.name!r} is not set"
            )
        ip = value.strip()
        try:
            ipaddress.ip_address(ip)
        except ValueError as exc:
            raise RuntimeError(
                f"invalid network configuration for camera {device.name!r}: {exc}"
            ) from exc
        return DeviceRuntime(device_id=device.id, ip=ip)


DiscoveryScan = Callable[[], Mapping[object, object]]


class TinyTuyaDeviceResolver:
    """Resolve a device location from TinyTuya UDP discovery announcements.

    Discovery is deliberately location-only: it passes no credentials to
    TinyTuya and returns no TinyTuya objects.  The configured LAN protocol is
    authoritative.  A differing reported ``version`` produces a warning but
    is never written to the profile or used to select a protocol.

    ``scan`` is an injection point for applications and tests that want to
    control when or how a discovery result is obtained.  When omitted, the
    public :func:`tinytuya.deviceScan` API is loaded lazily and used with
    polling and force-scanning disabled.
    """

    def __init__(self, scan: DiscoveryScan | None = None) -> None:
        self._scan = scan or self._tinytuya_scan

    @staticmethod
    def _tinytuya_scan() -> Mapping[object, object]:
        try:
            import tinytuya
        except ImportError as exc:
            raise RuntimeError(
                "TinyTuya LAN discovery requires the optional 'tinytuya' dependency"
            ) from exc
        # This listens for normal Tuya UDP announcements.  In particular,
        # forcescan=False avoids key-dependent active subnet probing, and
        # poll=False avoids status queries.
        return tinytuya.deviceScan(
            verbose=False,
            color=False,
            poll=False,
            forcescan=False,
        )

    def resolve(self, device: DeviceConfig) -> DeviceRuntime:
        discovered = self._scan()
        if not isinstance(discovered, Mapping):
            raise RuntimeError("TinyTuya LAN discovery returned an invalid result")

        for candidate_ip, metadata in discovered.items():
            if not isinstance(metadata, Mapping) or metadata.get("gwId") != device.id:
                continue
            ip = self._valid_discovered_ip(candidate_ip, device)
            self._warn_on_protocol_mismatch(device, metadata)
            return DeviceRuntime(device_id=device.id, ip=ip)

        raise RuntimeError(
            f"TinyTuya LAN discovery did not find configured device ID {device.id!r}"
        )

    @staticmethod
    def _valid_discovered_ip(candidate: object, device: DeviceConfig) -> str:
        if not isinstance(candidate, str):
            raise RuntimeError(
                f"TinyTuya LAN discovery returned an invalid IP for device {device.id!r}"
            )
        ip = candidate.strip()
        try:
            ipaddress.ip_address(ip)
        except ValueError as exc:
            raise RuntimeError(
                f"TinyTuya LAN discovery returned an invalid IP for device {device.id!r}: {exc}"
            ) from exc
        return ip

    @staticmethod
    def _warn_on_protocol_mismatch(
        device: DeviceConfig, metadata: Mapping[object, object]
    ) -> None:
        reported = metadata.get("version")
        if (
            isinstance(reported, str)
            and reported.strip()
            and reported.strip() != device.lan_protocol
        ):
            warnings.warn(
                f"TinyTuya discovery reports LAN protocol {reported.strip()!r} for "
                f"device {device.id!r}, but configured lan_protocol remains "
                f"{device.lan_protocol!r}",
                RuntimeWarning,
                stacklevel=3,
            )


class EnvironmentThenDiscoveryResolver:
    """Use a trusted legacy ``ip_env`` hint before falling back to discovery.

    A syntactically valid value from ``ip_env`` is deliberately trusted.  LAN
    identity probing may require a local key, which belongs to the credentials
    layer rather than a resolver.  Discovery therefore runs only when the
    environment hint is absent or invalid, never on every stream startup.
    """

    def __init__(
        self,
        environment: DeviceResolver | None = None,
        discovery: DeviceResolver | None = None,
    ) -> None:
        self._environment = environment or EnvironmentDeviceResolver()
        self._discovery = discovery or TinyTuyaDeviceResolver()

    def resolve(self, device: DeviceConfig) -> DeviceRuntime:
        try:
            return self._environment.resolve(device)
        except RuntimeError as hint_error:
            try:
                return self._discovery.resolve(device)
            except RuntimeError as discovery_error:
                raise RuntimeError(
                    f"cannot resolve device {device.id!r}: runtime IP hint is unusable "
                    f"({hint_error}); TinyTuya discovery failed: {discovery_error}"
                ) from discovery_error
