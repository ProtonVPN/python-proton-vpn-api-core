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
from __future__ import annotations

import base64
import random

from typing import Optional
from proton.vpn.session.certificates import Certificate
from proton.vpn.session.dataclasses import VPNCertificate
from proton.vpn.session.exceptions import (VPNCertificateExpiredError,
                                           VPNCertificateFingerprintError)
from proton.vpn.session.key_mgr import KeyHandler
from proton.vpn import logging


logger = logging.getLogger(__name__)


class VPNSecrets:
    """ Asymmetric crypto secrets generated locally by the client to :

        - connect to the VPN service
        - ask for a certificate to the API with the corresponding public key.
    """
    def __init__(self, ed25519_privatekey: Optional[str] = None):
        self._key_handler = (
            KeyHandler(base64.b64decode(ed25519_privatekey))
            if ed25519_privatekey
            else KeyHandler()
        )

    def get_ed5519_sk_pem(self, password: Optional[bytes] = None):
        """
        Returns the ed5519 private key in pem format,
        and encrypted if a password was passed.
        """
        return self._key_handler.get_ed25519_sk_pem(password)

    @property
    def wireguard_privatekey(self) -> str:
        """Wireguard private key encoded in base64.
            To be added locally by the user. The API route is not providing it.
        """
        return self._key_handler.x25519_sk_str

    @property
    def ed25519_privatekey(self) -> str:
        """Private key in ed25519 base64 format. used to check fingerprints"""
        return self._key_handler.ed25519_sk_str

    @property
    def ed25519_pk_pem(self) -> str:  # pylint: disable=missing-function-docstring
        return self._key_handler.ed25519_pk_pem

    @property
    def proton_fingerprint_from_x25519_pk(self):  # pylint: disable=missing-function-docstring
        return self._key_handler.get_proton_fingerprint_from_x25519_pk(
            self._key_handler.x25519_pk_bytes
        )

    @staticmethod
    def from_dict(dict_data: dict):  # pylint: disable=missing-function-docstring
        return VPNSecrets(dict_data["ed25519_privatekey"])

    def to_dict(self):  # pylint: disable=missing-function-docstring
        return {
            "ed25519_privatekey": self.ed25519_privatekey
        }


class VPNPubkeyCredentials:
    """ Class responsible to hold vpn public key API RAW certificates and
        its associated private key for authentication.
    """
    MINIMUM_VALIDITY_PERIOD_IN_SECS = 300
    # FIXME: We were asked to increase the certification duration  # pylint: disable=fixme
    #  to 7 days due to certificate refresh issues, until a proper fix is put in place.
    #  It should be reverted to 1 day.
    REFRESH_INTERVAL = 60 * 60 * 24 * 7
    REFRESH_RANDOMNESS = 0.22  # +/- 22%

    def __init__(self, api_certificate: VPNCertificate, secrets: VPNSecrets, strict: bool = True):
        self._api_certificate = api_certificate
        self._secrets = secrets

        self._certificate_obj = self._build_certificate(
            api_certificate,
            secrets,
            strict
        )

    @classmethod
    def _generate_random_component(cls):
        # 1 +/- 0.22*random  # nosec B311
        return 1 + cls.REFRESH_RANDOMNESS * (2 * random.random() - 1)  # nosec B311

    @classmethod
    def get_refresh_interval_in_seconds(cls):  # pylint: disable=missing-function-docstring
        return cls.REFRESH_INTERVAL * cls._generate_random_component()

    def _build_certificate(self, api_certificate, secrets, strict):
        fingerprint_from_secrets = secrets.proton_fingerprint_from_x25519_pk

        # Get fingerprint from Certificate public key
        certificate = Certificate(cert_pem=api_certificate.Certificate)
        fingerprint_from_certificate = certificate.proton_fingerprint

        # Refuse to store unmatching fingerprints when strict equal True
        if strict:
            if fingerprint_from_secrets != fingerprint_from_certificate:
                raise VPNCertificateFingerprintError

        return Certificate(cert_pem=api_certificate.Certificate)

    def get_ed25519_sk_pem(self, password: Optional[bytes] = None):
        """
        Returns the ed5519 private key in pem format,
        and encrypted if a password was passed.
        """
        return self._secrets.get_ed5519_sk_pem(password)

    @property
    def certificate_pem(self) -> str:
        """ X509 client certificate in PEM format, can be used
            to connect for client based authentication to the local agent

            :raises VPNCertificateNotAvailableError: : certificate cannot be found
                :class:`VPNSession` must be populated with :meth:`VPNSession.refresh`.
            :raises VPNCertificateExpiredError: : certificate is expired.
            :return: :class:`api_data.VPNCertificate.Certificate`
        """
        if not self._certificate_obj.has_valid_date:
            raise VPNCertificateExpiredError

        self._log_if_certificate_requires_to_be_refreshed_but_is_not_expired()
        return self._certificate_obj.get_as_pem()

    @property
    def openvpn_private_key(self) -> str:
        """ Get OpenVPN private key in pem format, directly usable in an
            OpenVPN configuration file.
        """
        self._log_if_certificate_requires_to_be_refreshed_but_is_not_expired()
        return self._secrets.get_ed5519_sk_pem()

    @property
    def wg_private_key(self) -> str:
        """ Get Wireguard private key in base64 format,
            directly usable in a wireguard configuration file. This key
            is tied to the Proton :class:`VPNCertCredentials` by its
            corresponding API certificate.

            :return: :class:`api_data.VPNSecrets.wireguard_privatekey`: Wireguard private key
                in base64 format.
        """
        self._log_if_certificate_requires_to_be_refreshed_but_is_not_expired()
        return self._secrets.wireguard_privatekey

    @property
    def ed_255519_private_key(self) -> str:  # pylint: disable=missing-function-docstring
        return self._secrets.ed25519_privatekey

    @property
    def certificate_validity_remaining(self) -> Optional[float]:
        """ remaining time the certificate is valid, in seconds.

            - < 0 : certificate is not valid anymore
            -  None we don't have a certificate.
        """
        return self._certificate_obj.validity_period

    @property
    def remaining_time_to_next_refresh(self) -> int:
        """Returns a timestamp of when the next refresh should be done."""
        return self._api_certificate.remaining_time_to_next_refresh

    @property
    def proton_extensions(self):  # pylint: disable=missing-function-docstring
        return self._certificate_obj.proton_extensions

    @property
    def certificate_duration(self) -> Optional[float]:
        """ certificate range in seconds, even if not valid anymore.

            - return `None` if we don't have a certificate
        """
        return self._certificate_obj.duration.total_seconds()

    def _log_if_certificate_requires_to_be_refreshed_but_is_not_expired(self):
        if (
            self._certificate_obj.validity_period
            <= VPNPubkeyCredentials.MINIMUM_VALIDITY_PERIOD_IN_SECS
        ):
            logger.warning(
                msg="Current certificate will expire.",
                category="CREDENTIALS",
                subcategory="CERTIFICATE", event="REQUIRE_REFRESH"
            )
