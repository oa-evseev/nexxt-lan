"""Home Assistant lifecycle adapter for Nexxt LAN."""

from __future__ import annotations

import logging
from functools import partial
from pathlib import Path

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import EVENT_HOMEASSISTANT_STOP, Platform
from homeassistant.core import Event, HomeAssistant
from homeassistant.exceptions import ConfigEntryNotReady

from nexxt import NexxtLanManager

from .const import CONF_CONFIG_PATH, DEFAULT_RTSP_HOST, DEFAULT_RTSP_PORT

_LOGGER = logging.getLogger(__name__)
PLATFORMS: list[Platform] = [Platform.CAMERA]


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Load config and start one shared in-process manager for the entry."""
    config_path = Path(entry.data[CONF_CONFIG_PATH])
    try:
        manager = await hass.async_add_executor_job(
            partial(
                NexxtLanManager.from_config_file,
                config_path,
                listen=(DEFAULT_RTSP_HOST, DEFAULT_RTSP_PORT),
            )
        )
        await manager.async_start()
    except (OSError, RuntimeError) as exc:
        raise ConfigEntryNotReady(f"Unable to start Nexxt LAN: {exc}") from exc

    entry.runtime_data = manager

    async def _async_stop(_event: Event) -> None:
        await manager.async_stop()

    entry.async_on_unload(
        hass.bus.async_listen_once(EVENT_HOMEASSISTANT_STOP, _async_stop)
    )
    entry.async_on_unload(entry.add_update_listener(_async_reload_entry))

    try:
        await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    except BaseException:
        await manager.async_stop()
        raise
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload entities before stopping their shared manager and listener."""
    if not await hass.config_entries.async_unload_platforms(entry, PLATFORMS):
        return False
    manager: NexxtLanManager = entry.runtime_data
    await manager.async_stop()
    return True


async def _async_reload_entry(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Reload the entry when its data or options are updated."""
    await hass.config_entries.async_reload(entry.entry_id)
