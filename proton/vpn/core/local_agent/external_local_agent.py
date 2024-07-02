"""
Local Agent module that uses Proton external local agent implementation.


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

# NOTE: linter warnings have been disabled because project is not yet fully
# deployable to the public, and if any hotfix are required these changes
# might end up in public repos, thus breaking other packages.
# TO-DO: Remove linter warnings once python3-local-agent has been moved to WG Package.
from proton.vpn.local_agent import AgentConnector  # noqa pylint: disable=import-error, no-name-in-module

from proton.vpn.core.session import VPNSession
from proton.vpn.core.local_agent.exceptions import LocalAgentConnectionError


class LocalAgent:  # pylint: disable=too-few-public-methods
    """This local agent uses an external library to connect to local agent servers."""

    async def connect(self, session: VPNSession, vpn_server_domain: str):
        """
        Establishes a TLS to the local agent instance running on the VPN server
        the user is currently connected to.
        """
        cert = session.vpn_account.vpn_credentials.pubkey_credentials.certificate_pem

        credentials = session.vpn_account.vpn_credentials.pubkey_credentials
        key = credentials.get_ed25519_sk_pem()

        try:
            await AgentConnector().connect(vpn_server_domain, key, cert)
        except ValueError as exc:
            raise LocalAgentConnectionError(
                f"Local agent connection to {vpn_server_domain} failed."
            ) from exc
