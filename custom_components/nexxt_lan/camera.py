"""Camera platform for Nexxt LAN."""

from __future__ import annotations

from homeassistant.components.camera import Camera, CameraEntityFeature
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from nexxt import ManagedCamera, NexxtLanManager

from .const import DOMAIN


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Create one entity per RTSP-enabled camera in the shared manager."""
    manager: NexxtLanManager = entry.runtime_data
    async_add_entities(NexxtLanCamera(manager, camera) for camera in manager.cameras)


class NexxtLanCamera(Camera):
    """Thin CameraEntity view of one manager publication."""

    _attr_should_poll = False
    _attr_supported_features = CameraEntityFeature.STREAM

    def __init__(self, manager: NexxtLanManager, camera: ManagedCamera) -> None:
        super().__init__()
        self._manager = manager
        self._camera = camera
        self._attr_name = camera.name
        self._attr_unique_id = camera.device_id
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, camera.device_id)},
            name=camera.name,
            manufacturer="Nexxt",
        )

    async def stream_source(self) -> str:
        """Return this camera's URL on the entry's shared RTSP listener."""
        return self._manager.stream_source(self._camera)
