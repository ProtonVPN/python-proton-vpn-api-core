"""
Proton VPN API.


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
from __future__ import annotations

import asyncio
import os
import ssl
import socket
from pathlib import Path
from tempfile import TemporaryDirectory

from proton.vpn.core.session import VPNSession

from proton.vpn import logging

logger = logging.getLogger(__name__)


class LocalAgentConnectionError(Exception):
    """
    Raised when the local agent TLS connection did not succeed.
    It has the original exception chained to it.
    """


class LocalAgent:  # pylint: disable=too-few-public-methods
    """Temporary Local Agent implementation."""

    _VPN_SERVER_PORT = 65432
    _VPN_SERVER_IP = "10.2.0.1"
    _TIMEOUT_IN_SECS = 10

    async def connect(self, session: VPNSession, vpn_server_domain: str):
        """
        Establishes a TLS to the local agent instance running on the VPN server
        the user is currently connected to.
        """
        loop = asyncio.get_running_loop()
        try:
            await loop.run_in_executor(
                None, self._connect_sync, session, vpn_server_domain
            )
        except (OSError, TimeoutError, ssl.SSLError) as exc:
            raise LocalAgentConnectionError(
                f"Local agent connection to {vpn_server_domain} failed."
            ) from exc

    def _connect_sync(self, session: VPNSession, vpn_server_domain: str):
        with TemporaryDirectory() as temp_dir:
            temp_dir = Path(temp_dir)

            # Write certificate to disk.
            cert = session.vpn_account.vpn_credentials.pubkey_credentials.certificate_pem
            cert_path = temp_dir / "cert.pem"
            with open(cert_path, "w", encoding="utf-8") as file:
                file.write(cert)

            # Write encrypted private key to disk.
            key_password = os.urandom(32)
            credentials = session.vpn_account.vpn_credentials.pubkey_credentials
            key = credentials.get_ed25519_sk_pem(key_password)
            key_path = temp_dir / "key.pem"
            with open(key_path, "wb") as file:
                file.write(key.encode("ascii"))

            # Write Proton VPN root cert to disk.
            ca_path = temp_dir / "ca.pem"
            with open(ca_path, "w", encoding="utf-8") as file:
                file.write(PROTON_VPN_ROOT_CERT)

            # Establish TLS to local agent instance running on the VPN server.
            self._establish_tls_connection(
                server_hostname=vpn_server_domain,
                cert_path=cert_path,
                key_path=key_path,
                key_password=key_password,
                ca_path=ca_path
            )

    def _establish_tls_connection(
            self, server_hostname: str, cert_path: str,
            key_path: str, key_password: bytes, ca_path: str
    ):  # pylint: disable=too-many-arguments
        with socket.create_connection(
                (self._VPN_SERVER_IP, self._VPN_SERVER_PORT), timeout=self._TIMEOUT_IN_SECS
        ) as sock:
            context = ssl.create_default_context()
            context.load_verify_locations(cafile=ca_path)
            context.load_cert_chain(certfile=cert_path, keyfile=key_path, password=key_password)
            with context.wrap_socket(sock, server_hostname=server_hostname):
                logger.info(f"Connected via local agent to {server_hostname}.")


PROTON_VPN_ROOT_CERT = """-----BEGIN CERTIFICATE-----
MIIFozCCA4ugAwIBAgIBATANBgkqhkiG9w0BAQ0FADBAMQswCQYDVQQGEwJDSDEV
MBMGA1UEChMMUHJvdG9uVlBOIEFHMRowGAYDVQQDExFQcm90b25WUE4gUm9vdCBD
QTAeFw0xNzAyMTUxNDM4MDBaFw0yNzAyMTUxNDM4MDBaMEAxCzAJBgNVBAYTAkNI
MRUwEwYDVQQKEwxQcm90b25WUE4gQUcxGjAYBgNVBAMTEVByb3RvblZQTiBSb290
IENBMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAt+BsSsZg7+AuqTq7
vDbPzfygtl9f8fLJqO4amsyOXlI7pquL5IsEZhpWyJIIvYybqS4s1/T7BbvHPLVE
wlrq8A5DBIXcfuXrBbKoYkmpICGc2u1KYVGOZ9A+PH9z4Tr6OXFfXRnsbZToie8t
2Xjv/dZDdUDAqeW89I/mXg3k5x08m2nfGCQDm4gCanN1r5MT7ge56z0MkY3FFGCO
qRwspIEUzu1ZqGSTkG1eQiOYIrdOF5cc7n2APyvBIcfvp/W3cpTOEmEBJ7/14RnX
nHo0fcx61Inx/6ZxzKkW8BMdGGQF3tF6u2M0FjVN0lLH9S0ul1TgoOS56yEJ34hr
JSRTqHuar3t/xdCbKFZjyXFZFNsXVvgJu34CNLrHHTGJj9jiUfFnxWQYMo9UNUd4
a3PPG1HnbG7LAjlvj5JlJ5aqO5gshdnqb9uIQeR2CdzcCJgklwRGCyDT1pm7eoiv
WV19YBd81vKulLzgPavu3kRRe83yl29It2hwQ9FMs5w6ZV/X6ciTKo3etkX9nBD9
ZzJPsGQsBUy7CzO1jK4W01+u3ItmQS+1s4xtcFxdFY8o/q1zoqBlxpe5MQIWN6Qa
lryiET74gMHE/S5WrPlsq/gehxsdgc6GDUXG4dk8vn6OUMa6wb5wRO3VXGEc67IY
m4mDFTYiPvLaFOxtndlUWuCruKcCAwEAAaOBpzCBpDAMBgNVHRMEBTADAQH/MB0G
A1UdDgQWBBSDkIaYhLVZTwyLNTetNB2qV0gkVDBoBgNVHSMEYTBfgBSDkIaYhLVZ
TwyLNTetNB2qV0gkVKFEpEIwQDELMAkGA1UEBhMCQ0gxFTATBgNVBAoTDFByb3Rv
blZQTiBBRzEaMBgGA1UEAxMRUHJvdG9uVlBOIFJvb3QgQ0GCAQEwCwYDVR0PBAQD
AgEGMA0GCSqGSIb3DQEBDQUAA4ICAQCYr7LpvnfZXBCxVIVc2ea1fjxQ6vkTj0zM
htFs3qfeXpMRf+g1NAh4vv1UIwLsczilMt87SjpJ25pZPyS3O+/VlI9ceZMvtGXd
MGfXhTDp//zRoL1cbzSHee9tQlmEm1tKFxB0wfWd/inGRjZxpJCTQh8oc7CTziHZ
ufS+Jkfpc4Rasr31fl7mHhJahF1j/ka/OOWmFbiHBNjzmNWPQInJm+0ygFqij5qs
51OEvubR8yh5Mdq4TNuWhFuTxpqoJ87VKaSOx/Aefca44Etwcj4gHb7LThidw/ky
zysZiWjyrbfX/31RX7QanKiMk2RDtgZaWi/lMfsl5O+6E2lJ1vo4xv9pW8225B5X
eAeXHCfjV/vrrCFqeCprNF6a3Tn/LX6VNy3jbeC+167QagBOaoDA01XPOx7Odhsb
Gd7cJ5VkgyycZgLnT9zrChgwjx59JQosFEG1DsaAgHfpEl/N3YPJh68N7fwN41Cj
zsk39v6iZdfuet/sP7oiP5/gLmA/CIPNhdIYxaojbLjFPkftVjVPn49RqwqzJJPR
N8BOyb94yhQ7KO4F3IcLT/y/dsWitY0ZH4lCnAVV/v2YjWAWS3OWyC8BFx/Jmc3W
DK/yPwECUcPgHIeXiRjHnJt0Zcm23O2Q3RphpU+1SO3XixsXpOVOYP6rJIXW9bMZ
A1gTTlpi7A==
-----END CERTIFICATE-----
"""
