"""
Reports VPN connection state transitions to telemetry.


Copyright (c) 2026 Proton AG

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
from typing import Optional

from proton.vpn.connection import states
from proton.vpn.core.refresher.telemetry_publisher import TELEMETRY_QUEUE_CAP
from proton.vpn.core.session_holder import SessionHolder
from proton.vpn.session.servers import TierEnum
from proton.vpn.platform.telemetry import (  # pylint: disable=no-name-in-module, import-error
    ConnectionEventBuilder, ConnectionOutcome, TelemetryEvents,
)


_USER_TIER_TO_WIRE = {
    TierEnum.FREE: "free",
    TierEnum.PLUS: "paid",
    TierEnum.PM: "internal",
}

_PROTOCOL_TO_WIRE = {
    "wireguard": "wireguard_udp",
    "protun-smart": "protun",
}

_SMART_PROTOCOL = "protun-smart"


class VPNConnectorTelemetry:  # pylint: disable=too-few-public-methods
    """Bridges connection state changes to the telemetry queue.

    :meth:`report_telemetry` is intended to be registered on the
    :class:`VPNConnector`'s publisher by the owning connector.
    """

    def __init__(
        self,
        session_holder: SessionHolder,
        telemetry: TelemetryEvents = None,
    ):
        self._session_holder = session_holder
        self._telemetry = telemetry or TelemetryEvents(TELEMETRY_QUEUE_CAP)
        self._pending: Optional[ConnectionEventBuilder] = None

    def report_telemetry(self, state: states.State):
        """Reports the state to telemetry.

        On `Connecting`, snapshots the dimensions and starts a builder.
        On a terminal state (`Connected`, `Error`, `Disconnected`), the
        pending builder is materialized with the outcome and submitted.
        Terminal states with no pending builder are dropped: this covers
        the post-`Connected` disconnect (already submitted at `Connected`)
        and any orphan terminal that never had a `Connecting` transition.
        """
        if isinstance(state, states.Connecting):
            connection = state.context.connection
            if connection is None:
                return
            protocol = connection.protocol
            self._pending = self._telemetry.connect_event(
                _PROTOCOL_TO_WIRE.get(protocol, protocol.replace("-", "_")),
                _USER_TIER_TO_WIRE.get(self._session_holder.user_tier, "unknown"),
                protocol == _SMART_PROTOCOL,
            )
            return

        if isinstance(state, states.Connected):
            outcome = ConnectionOutcome.Success
        elif isinstance(state, states.Error):
            outcome = ConnectionOutcome.Failure
        elif isinstance(state, states.Disconnected):
            outcome = ConnectionOutcome.Aborted
        else:
            return

        if self._pending is None:
            return

        self._telemetry.submit(self._pending.build(outcome))
        self._pending = None
