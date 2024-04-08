"""DataUpdateCoordinator for the wallbox integration."""

from __future__ import annotations

from collections.abc import Callable
from datetime import timedelta
from http import HTTPStatus
import logging
from typing import Any, Concatenate, ParamSpec, TypeVar

import requests
from time import monotonic


_LOGGER = logging.getLogger(__name__)

try:
    from wallbox.wallbox import Wallbox
except Exception:
    from wallbox import Wallbox
    _LOGGER.debug("BAD WALLBOX IMPORT")

from homeassistant.core import HomeAssistant, callback
from homeassistant.exceptions import ConfigEntryAuthFailed, HomeAssistantError
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator

from .const import (
    CHARGER_CURRENCY_KEY,
    CHARGER_DATA_KEY,
    CHARGER_ENERGY_PRICE_KEY,
    CHARGER_LOCKED_UNLOCKED_KEY,
    CHARGER_MAX_CHARGING_CURRENT_KEY,
    CHARGER_STATUS_DESCRIPTION_KEY,
    CHARGER_STATUS_ID_KEY,
    CODE_KEY,
    DOMAIN,
    UPDATE_INTERVAL,
    ChargerStatus,
)



# Translation of StatusId based on Wallbox portal code:
# https://my.wallbox.com/src/utilities/charger/chargerStatuses.js
CHARGER_STATUS: dict[int, ChargerStatus] = {
    0: ChargerStatus.DISCONNECTED,
    14: ChargerStatus.ERROR,
    15: ChargerStatus.ERROR,
    161: ChargerStatus.READY,
    162: ChargerStatus.READY,
    163: ChargerStatus.DISCONNECTED,
    164: ChargerStatus.WAITING,
    165: ChargerStatus.LOCKED,
    166: ChargerStatus.UPDATING,
    177: ChargerStatus.SCHEDULED,
    178: ChargerStatus.PAUSED,
    179: ChargerStatus.SCHEDULED,
    180: ChargerStatus.WAITING_FOR_CAR,
    181: ChargerStatus.WAITING_FOR_CAR,
    182: ChargerStatus.PAUSED,
    183: ChargerStatus.WAITING_IN_QUEUE_POWER_SHARING,
    184: ChargerStatus.WAITING_IN_QUEUE_POWER_SHARING,
    185: ChargerStatus.WAITING_IN_QUEUE_POWER_BOOST,
    186: ChargerStatus.WAITING_IN_QUEUE_POWER_BOOST,
    187: ChargerStatus.WAITING_MID_FAILED,
    188: ChargerStatus.WAITING_MID_SAFETY,
    189: ChargerStatus.WAITING_IN_QUEUE_ECO_SMART,
    193: ChargerStatus.CHARGING,
    194: ChargerStatus.CHARGING,
    195: ChargerStatus.CHARGING,
    196: ChargerStatus.DISCHARGING,
    209: ChargerStatus.LOCKED,
    210: ChargerStatus.LOCKED_CAR_CONNECTED,
}

_WallboxCoordinatorT = TypeVar("_WallboxCoordinatorT", bound="WallboxCoordinator")
_P = ParamSpec("_P")


def _require_authentication(
    func: Callable[Concatenate[_WallboxCoordinatorT, _P], Any],
) -> Callable[Concatenate[_WallboxCoordinatorT, _P], Any]:
    """Authenticate with decorator using Wallbox API."""

    def require_authentication(
        self: _WallboxCoordinatorT, *args: _P.args, **kwargs: _P.kwargs
    ) -> Any:
        """Authenticate using Wallbox API."""
        try:
            self.authenticate()
            return func(self, *args, **kwargs)
        except requests.exceptions.HTTPError as wallbox_connection_error:
            _LOGGER.debug("ISSUE AUTHENTICATING WALLBOX %s", wallbox_connection_error, exc_info=True)
            if wallbox_connection_error.response.status_code == HTTPStatus.FORBIDDEN:
                raise ConfigEntryAuthFailed from wallbox_connection_error
            raise ConnectionError from wallbox_connection_error
        except Exception as e:
            _LOGGER.debug("ISSUE AUTHENTICATING WALLBOX: UNKNOWN",exc_info=True)
            raise e


    return require_authentication


class WallboxCoordinator(DataUpdateCoordinator[dict[str, Any]]):
    """Wallbox Coordinator class."""

    def __init__(self, station: str, wallbox: Wallbox, hass: HomeAssistant) -> None:
        """Initialize."""
        self._station = station
        self._wallbox = wallbox

        super().__init__(
            hass,
            _LOGGER,
            name=DOMAIN,
            update_interval=timedelta(seconds=UPDATE_INTERVAL),
        )

    @property
    def update_interval(self) -> timedelta | None:
        """Interval between updates."""
        _LOGGER.debug("WALLBOX UPDATE INTERVAL GET %s", self._update_interval)
        return self._update_interval

    @update_interval.setter
    def update_interval(self, value: timedelta | None) -> None:
        """Set interval between updates."""
        _LOGGER.debug("WALLBOX UPDATE INTERVAL SETTER %s", value)
        self._update_interval = value
        self._update_interval_seconds = value.total_seconds() if value else None




    def authenticate(self) -> None:
        """Authenticate using Wallbox API."""
        _LOGGER.debug("Authenticating Wallbox connection.")
        self._wallbox.authenticate()

    def _validate(self) -> None:
        """Authenticate using Wallbox API."""
        _LOGGER.debug("Validating Wallbox connection.")
        try:
            self._wallbox.authenticate()
        except requests.exceptions.HTTPError as wallbox_connection_error:
            _LOGGER.debug("ISSUE VALIDATING WALLBOX %s", wallbox_connection_error,exc_info=True)
            if wallbox_connection_error.response.status_code == 403:
                raise InvalidAuth from wallbox_connection_error
            raise ConnectionError from wallbox_connection_error
        except Exception as e:
            _LOGGER.debug("ISSUE VALIDATING WALLBOX: UNKNOWN",exc_info=True)
            raise e


    async def async_validate_input(self) -> None:
        """Get new sensor data for Wallbox component."""
        await self.hass.async_add_executor_job(self._validate)

    @_require_authentication
    def _get_data(self) -> dict[str, Any]:

        _LOGGER.debug("Get new sensor data for Wallbox component.")
        """Get new sensor data for Wallbox component."""
        try:
            data: dict[str, Any] = self._wallbox.getChargerStatus(self._station)
        except:
            _LOGGER.debug("RETURN SAME DATA DUE TO ERROR Wallbox component.")
            return self.data

        data[CHARGER_MAX_CHARGING_CURRENT_KEY] = data[CHARGER_DATA_KEY][
            CHARGER_MAX_CHARGING_CURRENT_KEY
        ]
        data[CHARGER_LOCKED_UNLOCKED_KEY] = data[CHARGER_DATA_KEY][
            CHARGER_LOCKED_UNLOCKED_KEY
        ]
        data[CHARGER_ENERGY_PRICE_KEY] = data[CHARGER_DATA_KEY][
            CHARGER_ENERGY_PRICE_KEY
        ]
        data[CHARGER_CURRENCY_KEY] = (
            f"{data[CHARGER_DATA_KEY][CHARGER_CURRENCY_KEY][CODE_KEY]}/kWh"
        )

        data[CHARGER_STATUS_DESCRIPTION_KEY] = CHARGER_STATUS.get(
            data[CHARGER_STATUS_ID_KEY], ChargerStatus.UNKNOWN
        )
        return data

    async def _async_update_data(self) -> dict[str, Any]:
        """Get new sensor data for Wallbox component."""
        _LOGGER.debug(">>>>>>> _async_update_data")
        return await self.hass.async_add_executor_job(self._get_data)

    @callback
    def _schedule_refresh(self) -> None:
        """Schedule a refresh."""
        _LOGGER.debug(">>>>>>> _schedule_refresh")
        if self._update_interval_seconds is None:
            _LOGGER.debug(">>>>>>> _schedule_refresh: self._update_interval_seconds is None")
            return

        if self.config_entry and self.config_entry.pref_disable_polling:
            _LOGGER.debug(">>>>>>> _schedule_refresh : pref_disable_polling")
            return

        # We do not cancel the debouncer here. If the refresh interval is shorter
        # than the debouncer cooldown, this would cause the debounce to never be called
        self._async_unsub_refresh()

        # We use loop.call_at because DataUpdateCoordinator does
        # not need an exact update interval which also avoids
        # calling dt_util.utcnow() on every update.
        hass = self.hass
        loop = hass.loop

        next_refresh = (
                int(loop.time()) + self._microsecond + self._update_interval_seconds
        )
        self._unsub_refresh = loop.call_at(
            next_refresh, self.__wrap_handle_refresh_interval
        ).cancel

    @callback
    def __wrap_handle_refresh_interval(self) -> None:
        """Handle a refresh interval occurrence."""
        _LOGGER.debug(">>>>>>> __wrap_handle_refresh_interval")
        if self.config_entry:
            self.config_entry.async_create_background_task(
                self.hass,
                self._handle_refresh_interval(),
                name=f"{self.name} - {self.config_entry.title} - refresh",
                eager_start=True,
            )
        else:
            self.hass.async_create_background_task(
                self._handle_refresh_interval(),
                name=f"{self.name} - refresh",
                eager_start=True,
            )

    async def _handle_refresh_interval(self, _now: datetime | None = None) -> None:
        """Handle a refresh interval occurrence."""
        self._unsub_refresh = None
        _LOGGER.debug(">>>>>>> _handle_refresh_interval")
        await self._async_refresh(log_failures=True, scheduled=True)

    async def async_request_refresh(self) -> None:
        """Request a refresh.

        Refresh will wait a bit to see if it can batch them.
        """
        _LOGGER.debug(">>>>>>> async_request_refresh")
        await self._debounced_refresh.async_call()

    async def async_config_entry_first_refresh(self) -> None:
        """Refresh data for the first time when a config entry is setup.

        Will automatically raise ConfigEntryNotReady if the refresh
        fails. Additionally logging is handled by config entry setup
        to ensure that multiple retries do not cause log spam.
        """
        _LOGGER.debug("async_config_entry_first_refresh")
        await self._async_refresh(
            log_failures=False, raise_on_auth_failed=True, raise_on_entry_error=True
        )
        _LOGGER.debug(">>>>>>> async_config_entry_first_refresh")
        if self.last_update_success:
            _LOGGER.debug(">>>>>>> async_config_entry_first_refresh  self.last_update_success")
            return
        ex = ConfigEntryNotReady()
        ex.__cause__ = self.last_exception
        _LOGGER.debug(">>>>>>> async_config_entry_first_refresh  RAISE %s", ex)
        raise ex

    async def async_refresh(self) -> None:
        """Refresh data and log errors."""
        _LOGGER.debug(">>>>>>> async_refresh")
        await self._async_refresh(log_failures=True)

    async def _async_refresh(  # noqa: C901
            self,
            log_failures: bool = True,
            raise_on_auth_failed: bool = False,
            scheduled: bool = False,
            raise_on_entry_error: bool = False,
    ) -> None:
        """Refresh data."""
        _LOGGER.debug(">>>>>>> _async_refresh")
        self._async_unsub_refresh()
        self._debounced_refresh.async_cancel()

        if self._shutdown_requested or scheduled and self.hass.is_stopping:
            _LOGGER.debug(">>>>>>> _async_refresh self._shutdown_requested")
            return

        if log_timing := self.logger.isEnabledFor(logging.DEBUG):
            start = monotonic()

        auth_failed = False
        previous_update_success = self.last_update_success
        previous_data = self.data

        try:
            self.data = await self._async_update_data()

        except (TimeoutError, requests.exceptions.Timeout) as err:
            _LOGGER.debug(">>>>>>> _async_refresh EXCEPTION TimeoutError, %s", err)
            self.last_exception = err
            if self.last_update_success:
                if log_failures:
                    self.logger.error("Timeout fetching %s data", self.name)
                self.last_update_success = False

        except (aiohttp.ClientError, requests.exceptions.RequestException) as err:
            _LOGGER.debug(">>>>>>> _async_refresh EXCEPTION ClientError, %s", err)
            self.last_exception = err
            if self.last_update_success:
                if log_failures:
                    self.logger.error("Error requesting %s data: %s", self.name, err)
                self.last_update_success = False

        except urllib.error.URLError as err:
            self.last_exception = err
            _LOGGER.debug(">>>>>>> _async_refresh EXCEPTION URLError, %s", err)
            if self.last_update_success:
                if log_failures:
                    if err.reason == "timed out":
                        self.logger.error("Timeout fetching %s data", self.name)
                    else:
                        self.logger.error(
                            "Error requesting %s data: %s", self.name, err
                        )
                self.last_update_success = False

        except UpdateFailed as err:
            self.last_exception = err
            _LOGGER.debug(">>>>>>> _async_refresh EXCEPTION UpdateFailed, %s", err)
            if self.last_update_success:
                if log_failures:
                    self.logger.error("Error fetching %s data: %s", self.name, err)
                self.last_update_success = False

        except ConfigEntryError as err:
            self.last_exception = err
            _LOGGER.debug(">>>>>>> _async_refresh EXCEPTION ConfigEntryError, %s", err)
            if self.last_update_success:
                if log_failures:
                    self.logger.error(
                        "Config entry setup failed while fetching %s data: %s",
                        self.name,
                        err,
                    )
                self.last_update_success = False
            if raise_on_entry_error:
                _LOGGER.debug(">>>>>>> _async_refresh raise_on_entry_error!")
                raise

        except ConfigEntryAuthFailed as err:
            _LOGGER.debug(">>>>>>> _async_refresh EXCEPTION ConfigEntryAuthFailed, %s", err)
            auth_failed = True
            self.last_exception = err
            if self.last_update_success:
                if log_failures:
                    self.logger.error(
                        "Authentication failed while fetching %s data: %s",
                        self.name,
                        err,
                    )
                self.last_update_success = False
            if raise_on_auth_failed:
                raise

            if self.config_entry:
                self.config_entry.async_start_reauth(self.hass)
        except NotImplementedError as err:
            _LOGGER.debug(">>>>>>> _async_refresh EXCEPTION NotImplementedError, %s", err)
            self.last_exception = err
            raise err

        except Exception as err:  # pylint: disable=broad-except
            _LOGGER.debug(">>>>>>> _async_refresh EXCEPTION Exception, %s", err)
            self.last_exception = err
            self.last_update_success = False
            self.logger.exception(
                "Unexpected error fetching %s data: %s", self.name, err
            )

        else:
            if not self.last_update_success:
                self.last_update_success = True
                self.logger.info("Fetching %s data recovered", self.name)

        finally:
            if log_timing:
                self.logger.debug(
                    "Finished fetching %s data in %.3f seconds (success: %s)",
                    self.name,
                    monotonic() - start,
                    self.last_update_success,
                )
            if not auth_failed and self._listeners and not self.hass.is_stopping:
                _LOGGER.debug(">>>>>>> _async_refresh scheduling refresh")
                self._schedule_refresh()
            else:
                _LOGGER.debug(">>>>>>> _async_refresh !!!! NOT scheduling refresh")

        if not self.last_update_success and not previous_update_success:
            _LOGGER.debug(">>>>>>> _async_refresh RETURN as not self.last_update_success and not previous_update_success")
            return

        if (
                self.always_update
                or self.last_update_success != previous_update_success
                or previous_data != self.data
        ):
            self.async_update_listeners()
        else:
            _LOGGER.debug(
                ">>>>>>> _async_refresh NO UPDATE alwaysupdate %s, last_success : %s, prev_success: %s, prev_data equal last: %s",
            self.always_update,self.last_update_success, previous_update_success,  previous_data == self.data)

    @_require_authentication
    def _set_charging_current(self, charging_current: float) -> None:
        """Set maximum charging current for Wallbox."""
        try:
            self._wallbox.setMaxChargingCurrent(self._station, charging_current)
        except requests.exceptions.HTTPError as wallbox_connection_error:
            if wallbox_connection_error.response.status_code == 403:
                raise InvalidAuth from wallbox_connection_error
            raise wallbox_connection_error

    async def async_set_charging_current(self, charging_current: float) -> None:
        """Set maximum charging current for Wallbox."""
        await self.hass.async_add_executor_job(
            self._set_charging_current, charging_current
        )
        await self.async_request_refresh()

    @_require_authentication
    def _set_energy_cost(self, energy_cost: float) -> None:
        """Set energy cost for Wallbox."""

        self._wallbox.setEnergyCost(self._station, energy_cost)

    async def async_set_energy_cost(self, energy_cost: float) -> None:
        """Set energy cost for Wallbox."""
        await self.hass.async_add_executor_job(self._set_energy_cost, energy_cost)
        await self.async_request_refresh()

    @_require_authentication
    def _set_lock_unlock(self, lock: bool) -> None:
        """Set wallbox to locked or unlocked."""
        try:
            if lock:
                self._wallbox.lockCharger(self._station)
            else:
                self._wallbox.unlockCharger(self._station)
        except requests.exceptions.HTTPError as wallbox_connection_error:
            if wallbox_connection_error.response.status_code == 403:
                raise InvalidAuth from wallbox_connection_error
            raise wallbox_connection_error

    async def async_set_lock_unlock(self, lock: bool) -> None:
        """Set wallbox to locked or unlocked."""
        await self.hass.async_add_executor_job(self._set_lock_unlock, lock)
        await self.async_request_refresh()

    @_require_authentication
    def _pause_charger(self, pause: bool) -> None:
        """Set wallbox to pause or resume."""

        if pause:
            self._wallbox.pauseChargingSession(self._station)
        else:
            self._wallbox.resumeChargingSession(self._station)

    async def async_pause_charger(self, pause: bool) -> None:
        """Set wallbox to pause or resume."""
        await self.hass.async_add_executor_job(self._pause_charger, pause)
        await self.async_request_refresh()


class InvalidAuth(HomeAssistantError):
    """Error to indicate there is invalid auth."""
