from proton.sso import ProtonSSO
from proton.vpn.session import VPNSession


class VPNSessionController:

    def __init__(self, username=None, session=None):
        if session:
            self._session = session
            return

        self.__set_session(username)

    def __set_session(self, username):
        sso = ProtonSSO()

        if username is None:
            self._session = sso.get_default_session(override_class=VPNSession)
            return

        self._session = sso.get_session(username, override_class=VPNSession)

    def api_request(self, *args, **kwargs) -> dict:
        return self._session.api_request(*args, **kwargs)

    @property
    def vpn_logicals(self) -> dict:
        return self._session.api_request("/vpn/logicals")

    @property
    def vpn_loads(self) -> dict:
        return self._session.api_request("/vpn/loads")

    @property
    def vpn_client_config(self) -> dict:
        return self._session.api_request("/vpn/clientconfig")

    @property
    def vpn_location(self) -> dict:
        return self._session.api_request("/vpn/location")

    @property
    def vpn_sessions(self) -> dict:
        return self._session.api_request("/vpn/sessions")

    @property
    def vpn_streaming_services(self) -> dict:
        return self._session.api_request("/vpn/streamingservices")

    @property
    def notification(self) -> dict:
        return self._session.api_request("/core/v4/notifications")

    def login(self, user: str, password: str) -> bool:
        if self._session.authenticate(user, password):
            return True

        return False

    def logout(self):
        self._session.logout()

    def set2fa(self, code: str) -> bool:
        if self._session.provide_2fa(code):
            return True

        return False

    def refresh(self):
        self._session.refresh()

    @property
    def authenticated(self) -> bool:
        if self._session.authenticated:
            return True

        return False

    @property
    def username(self):
        return self._session.AccountName
