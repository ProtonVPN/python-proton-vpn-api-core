"""
Local Agent module.


Copyright (c) 2024 Proton AG

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
import proton.vpn.local_agent
import proton.vpn.logging

from proton.vpn.local_agent import (  # pylint: disable=no-name-in-module, import-error
    AgentConnector, AgentConnection, Status,
    State, Reason, ReasonCode, AgentFeatures,
    LocalAgentError, ExpiredCertificateError,
    PolicyAPIError, SyntaxAPIError, APIError,
    ConnectionDetails
)
from .listener import AgentListener

# Initialize logging for the local agent module, this forwards the rust
# logging to the python logging module.
proton.vpn.local_agent.init_logger(proton.vpn.logging.getLogger)

__all__ = [
    "AgentConnector", "AgentConnection", "Status",
    "State", "Reason", "ReasonCode", "AgentFeatures",
    "LocalAgentError", "ExpiredCertificateError",
    "PolicyAPIError", "SyntaxAPIError", "APIError",
    "ConnectionDetails", "AgentListener"
]
