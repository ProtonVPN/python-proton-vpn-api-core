import logging
from dataclasses import dataclass

from proton.vpn.session import VPNSession
from proton.sso import ProtonSSO


logger = logging.getLogger(__name__)


@dataclass
class LoginResult:
    success: bool
    authenticated: bool
    twofa_required: bool


class Session(VPNSession):
    # TODO: move the content of this class to VPNSession

    def login(self, username: str, password: str) -> LoginResult:
        if self.logged_in:
            logger.info("The user is already logged in.")
            return LoginResult(success=True, authenticated=True, twofa_required=False)

        if not self.authenticate(username, password):
            return LoginResult(success=False, authenticated=False, twofa_required=False)

        if self.needs_twofa:
            return LoginResult(success=False, authenticated=True, twofa_required=True)

        self.refresh()  # TODO: Laurent says we should not refresh the session manually
        return LoginResult(success=True, authenticated=True, twofa_required=False)

    def provide_2fa(self, code: str) -> LoginResult:
        valid_code = super().provide_2fa(code)
        if not valid_code:
            return LoginResult(success=False, authenticated=True, twofa_required=True)

        self.refresh()  # TODO: Laurent says we should not refresh the session manually
        return LoginResult(success=True, authenticated=True, twofa_required=False)

    @property
    def logged_in(self):
        return self.authenticated and not self.needs_twofa


class SessionHolder:
    """Holds the current session object, initializing it lazily when requested."""

    def __init__(self, session: Session = None):
        self._proton_sso = ProtonSSO()
        self._session = session

    def get_session_for(self, username:str) -> Session:
        self._session = self._proton_sso.get_session(account_name=username, override_class=Session)
        return self._session

    @property
    def session(self):
        if not self._session:
            self._session = self._proton_sso.get_default_session(override_class=Session)

        return self._session
