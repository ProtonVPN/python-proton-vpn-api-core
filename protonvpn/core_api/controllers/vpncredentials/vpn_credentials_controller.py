from proton.session.exceptions import (ProtonAPI2FANeeded,
                                       ProtonAPIAuthenticationNeeded)
from proton.vpn.session import VPNSession
from proton.sso import ProtonSSO

class VPNCredentialController:

    def __init__(self, username=None, wanted_cert_duration=None, session=None, vpnaccount=None):
        self._pem_cert = None
        self._wg_key = None
        self._openvpnkey = None
        self._session = self._get_vpnsession(username)

        # I no cert duration is indicated, try to guess it from the account,
        # otherwhise just use a default value.
        if wanted_cert_duration is None and self._session and self._session.authenticated:
            current_duration = self._session.vpn_account.vpn_credentials.pubkey_credentials.certificate_duration
            if current_duration is not None:
                self._cert_duration = int(current_duration/60)
            else:
                self._cert_duration = 1440
        else:
            self._cert_duration = wanted_cert_duration


    def _get_vpnsession(self, username:str=None) -> VPNSession:
        sso = ProtonSSO()
        if username is None:
            return sso.get_default_session(override_class=VPNSession)
        else:
            return sso.get_session(username, override_class=VPNSession)

    @property
    def certificate_info(self):
        # just make sure that we can access it.
        return self._session.vpn_account.vpn_credentials.pubkey_credentials

    @property
    def vpnaccount(self) -> 'VPNAccount':
        return self._session.vpn_account
