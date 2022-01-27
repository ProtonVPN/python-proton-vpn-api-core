from proton.session.exceptions import (ProtonAPI2FANeeded,
                                       ProtonAPIAuthenticationNeeded)
from protonvpn.vpnaccount import (VPNAccountReloadVPNData,
                                  VPNCertificateExpiredError,
                                  VPNCertificateNeedRefreshError,
                                  VPNCertificateNotAvailableError)
from protonvpn.vpnaccount.api_data import (VPNCertCredentialsFetcher,
                                           VPNSettingsFetcher)


class VPNCredentialController:

    def __init__(self, username=None, wanted_cert_duration=None, session=None, vpnaccount=None):
        self._pem_cert = None
        self._wg_key = None
        self._openvpnkey = None

        if username:
            from proton.sso import ProtonSSO
            sso = ProtonSSO()
            self._session = sso.get_session(username)

            from protonvpn.vpnaccount import VPNAccount
            self._account = VPNAccount(username)
        else:
            self._session = session
            self._account = vpnaccount

        # I no cert duration is indicated, try to guess it from the account,
        # otherwhise just use a default value.
        if wanted_cert_duration is None and self._session and self._account:
            current_duration = self._account.vpn_get_certificate_holder().vpn_certificate_duration
            if current_duration is not None:
                self._cert_duration = int(current_duration/60)
            else:
                self._cert_duration = 1440
        else:
            self._cert_duration = wanted_cert_duration

    def ReloadLogic(base_function):

        import functools
        @functools.wraps(base_function)
        def wrapped_function(self: 'CredentialController', *a, **kw):
            try:
                res = base_function(self, *a, **kw)
            except VPNCertificateNotAvailableError:
                f = VPNCertCredentialsFetcher(session=self._session, cert_duration=self._cert_duration)
                self._account.vpn_reload_cert_credentials(f.fetch())
                res = base_function(self, *a, **kw)
            except (VPNCertificateExpiredError, VPNCertificateNeedRefreshError):
                private_key = self._account.vpn_get_certificate_holder().get_vpn_client_private_ed25519_key()
                f = VPNCertCredentialsFetcher(session=self._session, cert_duration=self._cert_duration, _private_key=private_key)
                self._account.vpn_reload_cert_credentials(f.fetch())
                res = base_function(self, *a, **kw)
            except (VPNAccountReloadVPNData):
                f = VPNSettingsFetcher(session=self._session)
                self._account.vpn_reload_settings(f.fetch())
                res = base_function(self, *a, **kw)
            except ProtonAPIAuthenticationNeeded:
                raise
            except ProtonAPI2FANeeded:
                raise
            return res

        return wrapped_function

    @ReloadLogic
    def _refresh_pem_certificate(self) -> None:
        self._account.vpn_get_certificate_holder().vpn_client_api_pem_certificate

    @ReloadLogic
    def _refresh_vpn_settings(self) -> None:
        self._account.vpn_get_username_and_password()

    def refresh_vpn_credentials(self) -> None:
        self._refresh_pem_certificate()
        self._refresh_vpn_settings()

    @property
    def certificate_info(self):
        # just make sure that we can access it.
        self.refresh_vpn_credentials()
        return self._account.vpn_get_certificate_holder()

    @property
    def vpnaccount(self) -> 'VPNAccount':
        return self._account
