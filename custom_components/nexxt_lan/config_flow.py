"""Config flow for Nexxt LAN."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.config_entries import ConfigFlowResult

from nexxt import validate_config_file

from .const import CONF_CONFIG_PATH, DOMAIN, NAME

_LOGGER = logging.getLogger(__name__)


class NexxtLanConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Configure Nexxt LAN from an existing versioned config file."""

    VERSION = 1

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Accept and validate an explicit nexxt-lan config path."""
        errors: dict[str, str] = {}
        if user_input is not None:
            path = Path(user_input[CONF_CONFIG_PATH]).expanduser()
            try:
                await self.hass.async_add_executor_job(validate_config_file, path)
                canonical_path = str(path.resolve(strict=True))
            except (OSError, RuntimeError) as exc:
                _LOGGER.debug("Nexxt LAN config validation failed: %s", exc)
                errors["base"] = "invalid_config"
            else:
                await self.async_set_unique_id(canonical_path)
                self._abort_if_unique_id_configured()
                return self.async_create_entry(
                    title=NAME,
                    data={CONF_CONFIG_PATH: canonical_path},
                )

        schema = vol.Schema(
            {
                vol.Required(
                    CONF_CONFIG_PATH,
                    default=(user_input or {}).get(CONF_CONFIG_PATH, ""),
                ): str
            }
        )
        return self.async_show_form(step_id="user", data_schema=schema, errors=errors)
