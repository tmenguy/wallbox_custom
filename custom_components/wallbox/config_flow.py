"""Config flow for Wallbox integration."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import voluptuous as vol
try:
    from .wallbox.wallbox import Wallbox
except Exception:
    from wallbox import Wallbox

from homeassistant.config_entries import SOURCE_REAUTH, ConfigFlow, ConfigFlowResult
from homeassistant.const import CONF_PASSWORD, CONF_USERNAME
from homeassistant.core import HomeAssistant

from .const import CONF_STATION, DOMAIN
from .coordinator import InvalidAuth, async_validate_input

COMPONENT_DOMAIN = DOMAIN

STEP_USER_DATA_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_STATION): str,
        vol.Required(CONF_USERNAME): str,
        vol.Required(CONF_PASSWORD): str,
    }
)


async def validate_input(hass: HomeAssistant, data: dict[str, Any]) -> dict[str, str]:
    """Validate the user input allows to connect.

    Data has the keys from STEP_USER_DATA_SCHEMA with values provided by the user.
    """
    wallbox = Wallbox(data["username"], data["password"])

    await async_validate_input(hass, wallbox)

    # Return info that you want to store in the config entry.
    return {"title": "Wallbox Portal"}


class WallboxConfigFlow(ConfigFlow, domain=COMPONENT_DOMAIN):
    """Handle a config flow for Wallbox."""

    async def async_step_reauth(
        self, entry_data: Mapping[str, Any]
    ) -> ConfigFlowResult:
        """Perform reauth upon an API authentication error."""
        return await self.async_step_user()

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle the initial step."""
        if user_input is None:
            return self.async_show_form(
                step_id="user",
                data_schema=STEP_USER_DATA_SCHEMA,
            )

        errors = {}

        try:
            await self.async_set_unique_id(user_input["station"])
            if self.source != SOURCE_REAUTH:
                self._abort_if_unique_id_configured()
                info = await validate_input(self.hass, user_input)
                return self.async_create_entry(title=info["title"], data=user_input)
            reauth_entry = self._get_reauth_entry()
            if user_input["station"] == reauth_entry.data[CONF_STATION]:
                return self.async_update_reload_and_abort(reauth_entry, data=user_input)
            errors["base"] = "reauth_invalid"
        except ConnectionError:
            errors["base"] = "cannot_connect"
        except InvalidAuth:
            errors["base"] = "invalid_auth"

        return self.async_show_form(
            step_id="user",
            data_schema=STEP_USER_DATA_SCHEMA,
            errors=errors,
        )
