import logging

from proton.vpn.session import VPNSession
from proton.sso import ProtonSSO


logger = logging.getLogger(__name__)


class SessionHolder:
    """Holds the current session object, initializing it lazily when requested."""

    def __init__(self, session: VPNSession = None):
        self._proton_sso = ProtonSSO()
        self._session = session

    def get_session_for(self, username: str) -> VPNSession:
        self._session = self._proton_sso.get_session(account_name=username, override_class=VPNSession)
        return self._session

    @property
    def session(self):
        if not self._session:
            self._session = self._proton_sso.get_default_session(override_class=VPNSession)

        return self._session
