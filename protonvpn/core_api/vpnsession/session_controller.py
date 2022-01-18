from proton.sso import ProtonSSO
from proton.session import Session
from typing import Optional
from enum import Enum
from proton.session import Session
from proton.session.exceptions import ProtonAPIAuthenticationNeeded
from protonvpn.vpnaccount.vpnaccount import VPNAccount, VPNAccountReloadVPNData, VPNUserPass
from protonvpn.vpnaccount.api_data import VPNSettings, VPNCertCredentials
from protonvpn.vpnaccount.api_data import VPNSettingsFetcher

class VPNSessionControllerState(Enum):
    CAN_VPN_LOGIN=0
    NEED_API_LOGIN=1

class VPNSessionController:
    """ Responsible to:
        - control Proton API Session lifecycle.
        - offer interfaces to login/logout from the API.
        - send exceptions to the user when we cannot login
        - Unify the notion of VPN Session (Account data) and API Session through a single class.
    """
    def __init__(self):
        self._sso = ProtonSSO()
        self._session = self._sso.get_default_session()
        if self._session.AccountName is not None:
            self._vpnaccount = VPNAccount(self._session.AccountName)
        else:
            self._vpnaccount = None

    @property
    def username(self) -> Optional[str]:
        """ To which user name this VPNSession belongs to ?
        """
        return self._session.AccountName

    def _reload_vpn_settings_from_api(self):
        settings=VPNSettingsFetcher(session=self._session).fetch()
        self._vpnaccount.reload_vpn_settings(settings)

    def get_vpn_username_and_password(self) -> VPNUserPass:
        """ Get the vpn user and password of the session. Needs to be logged in
            otherwhise will throw ProtonAPIAuthenticationNeeded
        """
        try:
            user_pass=self._vpnaccount.get_username_and_password()
        except VPNAccountReloadVPNData:
            self._reload_vpn_settings_from_api()
            user_pass=self._vpnaccount.get_username_and_password()
        return user_pass

    def get_tier(self) -> int:
        """ Get the tier of the session. Needs a logged in session otherwhise
            will throw ProtonAPIAuthenticationNeeded
        """
        try:
            tier=self._vpnaccount.max_tier
        except VPNAccountReloadVPNData:
            self._reload_vpn_settings_from_api()
            tier=self._vpnaccount.max_tier
        return tier

    def login(self, username, password) -> bool:
        """ Login to the API, return True if logged in, False if
            password was wrong.
        """
        logged_in=self._session.authenticate(username, password)
        if self._vpnaccount is None and logged_in:
            self._vpnaccount = VPNAccount(username)
        return logged_in

    def logout(self):
        self._session.logout()
        self._vpnaccount.clear()

    @property
    def state(self):
        """ Return the state of the session. If we can get some credentials, we assume that 
            we can login on the VPN, otherwhise try to reload them from the API. If this fails,
            assume that we need to login on the API.
        """
        if self.username is None:
            return VPNSessionControllerState.NEED_API_LOGIN

        try:
            user_pass=self._vpnaccount.get_username_and_password()
            return VPNSessionControllerState.CAN_VPN_LOGIN
        except VPNAccountReloadVPNData:
            try:
                self._reload_vpn_settings_from_api()
                return VPNSessionControllerState.CAN_VPN_LOGIN
            except ProtonAPIAuthenticationNeeded:
                return VPNSessionControllerState.NEED_API_LOGIN

    @property
    def session(self) -> Session:
        return self._session

