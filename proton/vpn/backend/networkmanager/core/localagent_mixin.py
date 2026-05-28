"""
Base class for VPN connections created with NetworkManager.


Copyright (c) 2023 Proton AG

This file is part of Proton VPN.

Proton VPN is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Proton VPN is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with ProtonVPN.  If not, see <https://www.gnu.org/licenses/>.
"""
import asyncio
import logging
import random

from concurrent import futures

from proton.vpn.connection import events
from proton.vpn.connection.events import EventContext
from proton.vpn.connection.exceptions \
    import FeatureError, FeaturePolicyError, FeatureSyntaxError
from proton.vpn.core.settings.features import Features
from proton.vpn.session.servers.types import TierEnum

from proton.vpn.backend.networkmanager.core.local_agent import (
    AgentListener, Status, ExpiredCertificateError, NotYetValidCertificateError, AgentFeatures,
    ReasonCode, PolicyAPIError, SyntaxAPIError, APIError, State
)

logger = logging.getLogger(__name__)

TWOFA_REASON_CODES = [
    ReasonCode.REASON_CODE_2FA_UNSPECIFIED,
    ReasonCode.REASON_CODE_2FA_EXPIRED,
    ReasonCode.REASON_CODE_2FA_SITUATION_CHANGED
]


class LocalAgentMixin:  # pylint: disable=too-few-public-methods
    """
    This mixin provides the functionality to start and stop the local agent
    client and to listen for status updates and errors from the local agent
    server.
    """
    def __init__(self, user_tier: TierEnum):
        self._user_tier = user_tier
        self._agent_listener = AgentListener(
            on_status=self.__on_local_agent_status,
            on_error=self.__on_local_agent_error
        )

    async def _start_local_agent_listener(self):
        """
        This method starts the local agent listener and waits for it to
        complete.
        """
        if self._agent_listener.is_running:  # noqa: E501 # pylint: disable=line-too-long # nosemgrep: python.lang.maintainability.is-function-without-parentheses.is-function-without-parentheses
            logger.info("Closing existing agent connection...")
            await self._agent_listener.stop()

        logger.info("Waiting for agent status from %s...",
                    self._vpnserver.domain)
        context = EventContext(connection=self)

        agent_connection_drops = 0
        while True:
            if not await self.__attempt_to_connect_to_listener(context):
                return

            if not await self.__attempt_to_request_connection_features(context):
                return

            if not await self.__attempt_to_listen(context):
                agent_connection_drops += 1
                # nosemgrep: gitlab.bandit.B311
                sleep_seconds = random.uniform(0, 10)  # nosec B311
                logger.warning(
                    "Agent connection dropped (#%s). Retrying in %.1f seconds.",
                    agent_connection_drops, sleep_seconds
                )
                await asyncio.sleep(sleep_seconds)
                continue

            return

    # Absorb CancelledError before it is logged by Future's done callback handler
    def _handle_future_result(self, future: futures.Future):
        try:
            future.result()
        except futures.CancelledError:
            pass

    def _async_start_local_agent_listener(self):
        """
        This schedules the local agent listener to start, but it will not wait
        for it.
        """
        future = asyncio.run_coroutine_threadsafe(
            self._start_local_agent_listener(),
            self._asyncio_loop
        )
        future.add_done_callback(self._handle_future_result)

    def _async_stop_local_agent_listener(self):
        """
        This schedules the local agent listener to stop, but it will not wait
        for it.
        """
        future = asyncio.run_coroutine_threadsafe(
            self._agent_listener.stop(),
            self._asyncio_loop
        )
        future.add_done_callback(self._handle_future_result)

    async def _request_connection_features(self, features: Features):
        if self._user_tier == TierEnum.FREE:
            # Local agent server raises an error if features are requested
            # for free users, even if they are the default ones.
            # Skipping requesting features causes using default ones.
            logger.info("Using default VPN connection features.")
            return

        logger.info("Requesting VPN connection features...")
        agent_features = self.__get_agent_features(features)
        await self._agent_listener.request_features(agent_features)
        logger.info("VPN connection features requested.")

    def __on_local_agent_status(self, status: Status):
        """The local agent listener calls this method whenever a new status is
        read from the local agent connection."""
        logger.info("Agent status received: %s", status)

        context = EventContext(
            connection=self,
            connection_details=status.connection_details,
            forwarded_port=status.features.forwarded_port if status.features else None
        )

        if status.state == State.CONNECTED:
            self._notify_subscribers_threadsafe(events.Connected(context))

        elif status.state == State.HARD_JAILED:
            self.__handle_hard_jailed_state(status)

    def __handle_hard_jailed_state(self, status: Status):
        context = EventContext(connection=self,
                               connection_details=status.connection_details)
        if status.reason.code == ReasonCode.CERTIFICATE_EXPIRED:
            self._notify_subscribers_threadsafe(
                events.ExpiredCertificate(context)
            )
        elif status.reason.code in TWOFA_REASON_CODES:
            self._notify_subscribers_threadsafe(
                events.TwoFARequired(context)
            )
        elif self.__has_reached_max_amount_of_concurrent_vpn_connections(status.reason.code):
            self._notify_subscribers_threadsafe(
                events.MaximumSessionsReached(context)
            )
        else:
            self._notify_subscribers_threadsafe(
                events.UnexpectedError(context)
            )

    def __has_reached_max_amount_of_concurrent_vpn_connections(
            self, code: ReasonCode) -> bool:
        """Check if a user has reached the maximum number of concurrent VPN
        sessions/connections permitted for the current tier."""
        return code in (
            ReasonCode.MAX_SESSIONS_UNKNOWN,
            ReasonCode.MAX_SESSIONS_FREE,
            ReasonCode.MAX_SESSIONS_BASIC,
            ReasonCode.MAX_SESSIONS_PLUS,
            ReasonCode.MAX_SESSIONS_VISIONARY,
            ReasonCode.MAX_SESSIONS_PRO
        )

    def __on_local_agent_error(self, error: Exception):
        """
        The local agent listener calls this method whenever a new error message
        read from the local agent connection.

        :param error: The error received from the local agent.
        """
        event = self.__get_event_from_error_message(error)
        self._notify_subscribers_threadsafe(event)

    def __get_event_from_error_message(self, error: Exception) -> events.Event:
        exception_message = str(error)

        if isinstance(error, PolicyAPIError):
            new_error = FeaturePolicyError(exception_message)
        elif isinstance(error, SyntaxAPIError):
            new_error = FeatureSyntaxError(exception_message)
        elif isinstance(error, APIError):
            new_error = FeatureError(exception_message)
        else:
            new_error = Exception(exception_message)

        return events.UnexpectedError(EventContext(error=new_error,
                                                   connection=self))

    async def __attempt_to_connect_to_listener(self,
                                               context: EventContext) -> bool:
        try:
            await self._agent_listener.connect(
                self._vpnserver.domain, self._vpncredentials.pubkey_credentials
            )
        except ExpiredCertificateError:
            self._notify_subscribers_threadsafe(
                events.ExpiredCertificate(context))
            return False
        except NotYetValidCertificateError:
            self._notify_subscribers_threadsafe(
                events.NotYetValidCertificate(context))
            return False
        except TimeoutError:
            logger.info("Connect timeout")
            self._notify_subscribers_threadsafe(events.Timeout(context))
            return False
        except Exception:
            self._notify_subscribers_threadsafe(
                events.UnexpectedError(context))
            raise

        return True

    async def __attempt_to_request_connection_features(self,
                                                       context: EventContext) -> bool:
        try:
            await self._request_connection_features(self.settings.features)
        except TimeoutError:
            self._notify_subscribers_threadsafe(events.Timeout(context))
            return False
        except Exception:
            self._notify_subscribers_threadsafe(
                events.UnexpectedError(context))
            raise

        return True

    async def __attempt_to_listen(self, context: EventContext) -> bool:
        try:
            await self._agent_listener.listen()
            return True
        except TimeoutError:
            return False
        except Exception:
            self._notify_subscribers_threadsafe(
                events.UnexpectedError(context))
            raise

    def __get_agent_features(self, features: Features) -> AgentFeatures:
        randomized_nat = (not features.moderate_nat
                          if features.moderate_nat is not None else None)

        return AgentFeatures(
            netshield_level=features.netshield,
            randomized_nat=randomized_nat,
            split_tcp=features.vpn_accelerator,
            port_forwarding=features.port_forwarding,
            bouncing=self._vpnserver.label,
            jail=None  # Currently not in use
        )
