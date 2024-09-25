"""
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
import json
import pathlib

import pytest
from proton.vpn.session import VPNSession, VPNPubkeyCredentials
from proton.vpn.session.fetcher import (
    VPNCertificate, VPNSessions, VPNSettings
)
from proton.vpn.session.credentials import VPNSecrets
from proton.vpn.session.dataclasses import VPNLocation
from proton.vpn.session.certificates import Certificate
from proton.vpn.session.exceptions import (
    VPNCertificateExpiredError, VPNCertificateFingerprintError,
    VPNCertificateError
)

DATA_DIR = pathlib.Path(__file__).parent.absolute() / 'data'
with open(DATA_DIR / 'api_cert_response.json', 'r') as f:
    VPN_CERTIFICATE_API_RESPONSE = json.load(f)
    del VPN_CERTIFICATE_API_RESPONSE["Code"]
with open(DATA_DIR / 'api_vpnsettings_response.json', 'r') as f:
    VPN_API_RESPONSE = json.load(f)
    del VPN_API_RESPONSE["Code"]
with open(DATA_DIR / 'api_vpnsessions_response.json', 'r') as f:
    VPN_SESSIONS_API_RESPONSE = json.load(f)
    del VPN_SESSIONS_API_RESPONSE["Code"]
with open(DATA_DIR / 'api_vpn_location_response.json', 'r') as f:
    VPN_LOCATION_API_RESPONSE = json.load(f)
    del VPN_LOCATION_API_RESPONSE["Code"]
with open(DATA_DIR / 'vpn_secrets.json', 'r') as f:
    VPN_SECRETS_DICT = json.load(f)


class TestVpnAccountSerialize:

    def test_fingerprints(self):
        # Check if our fingerprints are matching for secrets, API and Certificate
        # Get fingerprint from the secrets. Wireguard private key from the API is in ED25519 FORMAT ?
        private_key = VPN_SECRETS_DICT["ed25519_privatekey"]
        vpn_secrets = VPNSecrets(private_key)

        fingerprint_from_secrets = vpn_secrets.proton_fingerprint_from_x25519_pk
        # Get fingerprint from API
        fingerprint_from_api = VPN_CERTIFICATE_API_RESPONSE["ClientKeyFingerprint"]
        # Get fingerprint from Certificate
        certificate = Certificate(cert_pem=VPN_CERTIFICATE_API_RESPONSE["Certificate"])
        fingerprint_from_certificate = certificate.proton_fingerprint
        assert fingerprint_from_api == fingerprint_from_certificate
        assert fingerprint_from_secrets == fingerprint_from_certificate

    def test_vpnaccount_from_dict(self):
        vpnaccount = VPNSettings.from_dict(VPN_API_RESPONSE)
        assert vpnaccount.VPN.Name == "test"
        assert vpnaccount.VPN.Password == "passwordtest"
    
    def test_vpnaccount_to_dict(self):
        assert VPNSettings.from_dict(VPN_API_RESPONSE).to_dict() == VPN_API_RESPONSE

    def test_vpncertificate_from_dict(self):
        cert = VPNCertificate.from_dict(VPN_CERTIFICATE_API_RESPONSE)
        assert cert.SerialNumber == VPN_CERTIFICATE_API_RESPONSE["SerialNumber"]
        assert cert.ClientKeyFingerprint == VPN_CERTIFICATE_API_RESPONSE["ClientKeyFingerprint"]
        assert cert.ClientKey == VPN_CERTIFICATE_API_RESPONSE["ClientKey"]
        assert cert.Certificate == VPN_CERTIFICATE_API_RESPONSE["Certificate"]
        assert cert.ExpirationTime == VPN_CERTIFICATE_API_RESPONSE["ExpirationTime"]
        assert cert.RefreshTime == VPN_CERTIFICATE_API_RESPONSE["RefreshTime"]
        assert cert.Mode == VPN_CERTIFICATE_API_RESPONSE["Mode"]
        assert cert.DeviceName == VPN_CERTIFICATE_API_RESPONSE["DeviceName"]
        assert cert.ServerPublicKeyMode == VPN_CERTIFICATE_API_RESPONSE["ServerPublicKeyMode"]
        assert cert.ServerPublicKey == VPN_CERTIFICATE_API_RESPONSE["ServerPublicKey"]

    def test_vpncertificate_to_dict(self):
        assert VPNCertificate.from_dict(VPN_CERTIFICATE_API_RESPONSE).to_dict() == VPN_CERTIFICATE_API_RESPONSE

    def test_secrets_from_dict(self):
        secrets = VPNSecrets.from_dict(VPN_SECRETS_DICT)
        assert secrets.ed25519_privatekey == "rNW3dL5A3dUrQX3ZKbVAFLjSFJdvDU5JzjrRrnI+cos="

    def test_secrets_to_dict(self):
        assert VPNSecrets.from_dict(VPN_SECRETS_DICT).to_dict() == VPN_SECRETS_DICT

    def test_sessions_from_dict(self):
        sessions = VPNSessions.from_dict(VPN_SESSIONS_API_RESPONSE)
        assert(len(sessions.Sessions)==2)
        assert(sessions.Sessions[0].ExitIP=='1.2.3.4')
        assert(sessions.Sessions[1].ExitIP=='5.6.7.8')

    def test_location_from_dict(self):
        location = VPNLocation.from_dict(VPN_LOCATION_API_RESPONSE)
        assert location.IP == VPN_LOCATION_API_RESPONSE["IP"]
        assert location.Country == VPN_LOCATION_API_RESPONSE["Country"]
        assert location.ISP == VPN_LOCATION_API_RESPONSE["ISP"]

    def test_location_to_dict(self):
        # We delete it because the VPNLocation does not contain these two properties,
        # even though the API response returns these values,
        del VPN_LOCATION_API_RESPONSE["Lat"]
        del VPN_LOCATION_API_RESPONSE["Long"]

        assert VPNLocation.from_dict(VPN_LOCATION_API_RESPONSE).to_dict() == VPN_LOCATION_API_RESPONSE


class TestVpnAccount:
    def test_vpn_session___setstate__(self):
        vpnsession = VPNSession()
        vpndata={
            "vpn" : {
                "vpninfo": VPN_API_RESPONSE,
                "certificate": VPN_CERTIFICATE_API_RESPONSE,
                "location": VPN_LOCATION_API_RESPONSE,
                "secrets": VPN_SECRETS_DICT
            }
        }
        vpnsession.__setstate__(vpndata)

        vpn_account = vpnsession.vpn_account
        assert vpn_account.max_tier == 0
        assert vpn_account.max_connections == 2
        assert vpn_account.plan_name == vpndata["vpn"]["vpninfo"]["VPN"]["PlanName"]
        assert vpn_account.plan_title == vpndata["vpn"]["vpninfo"]["VPN"]["PlanTitle"]
        assert not vpn_account.delinquent
        assert vpn_account.location.to_dict() == vpndata["vpn"]["location"]
        vpncredentials = vpnsession.vpn_account.vpn_credentials
        assert vpncredentials.userpass_credentials.username == vpndata["vpn"]["vpninfo"]["VPN"]["Name"]
        assert vpncredentials.userpass_credentials.password == vpndata["vpn"]["vpninfo"]["VPN"]["Password"]
        assert vpncredentials.pubkey_credentials.ed_255519_private_key == vpndata["vpn"]["secrets"]["ed25519_privatekey"]


class TestPubkeyCredentials:
    def test_certificate_fingerprint_mismatch(self):
        # Generate a new keypair. This means its fingerprint won't match the one
        # from /vpn/v1/certificate.
        with pytest.raises(VPNCertificateFingerprintError):
            VPNPubkeyCredentials(
                api_certificate=VPNCertificate.from_dict(VPN_CERTIFICATE_API_RESPONSE),
                # A new keypair is generated: its fingerprint won't match the one returned by /vpn/v1/certificate.
                secrets=VPNSecrets(),
            )

    def test_certificate_duration(self):
        pubkey_credentials = VPNPubkeyCredentials(
            api_certificate=VPNCertificate.from_dict(VPN_CERTIFICATE_API_RESPONSE),
            # A new keypair is generated: its fingerprint won't match the one returned by /vpn/v1/certificate.
            secrets=VPNSecrets.from_dict(VPN_SECRETS_DICT),
        )

        assert(pubkey_credentials.certificate_duration == 86401.0)

    def test_expired_certificate(self):
        with pytest.raises(VPNCertificateExpiredError):
            pubkey_credentials = VPNPubkeyCredentials(
                api_certificate=VPNCertificate.from_dict(VPN_CERTIFICATE_API_RESPONSE),
                # A new keypair is generated: its fingerprint won't match the one returned by /vpn/v1/certificate.
                secrets=VPNSecrets.from_dict(VPN_SECRETS_DICT),
            )
            pubkey_credentials.certificate_pem()
