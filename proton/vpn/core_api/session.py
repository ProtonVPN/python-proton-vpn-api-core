"""
Proton VPN Session API.
"""
import distro

from proton.vpn.session import VPNSession
from proton.sso import ProtonSSO

DISTRIBUTION = distro.id()
VERSION = distro.version()


class SessionHolder:
    """Holds the current session object, initializing it lazily when requested."""

    def __init__(self, session: VPNSession = None):

        self._proton_sso = ProtonSSO(
            appversion="linux-vpn@4.0.0",
            user_agent=f"ProtonVPN/4.0.0 (Linux; {DISTRIBUTION}/{VERSION})"
        )
        self._session = session

    def get_session_for(self, username: str) -> VPNSession:
        """
        Returns the session for the specified user.
        :param username: Proton account username.
        :return:
        """
        self._session = self._proton_sso.get_session(
            account_name=username,
            override_class=VPNSession
        )
        return self._session

    @property
    def session(self) -> VPNSession:
        """Returns the current session object."""
        if not self._session:
            self._session = self._proton_sso.get_default_session(
                override_class=VPNSession
            )

        return self._session
