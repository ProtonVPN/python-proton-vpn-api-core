class VPNSessionController:

    def __init__(self, username=None, session=None):
        if session:
            self._session = session
            return

        self.__set_session(username)

    def __set_session(self, username):
        from proton.sso import ProtonSSO

        sso = ProtonSSO()

        if username is None:
            self._session = sso.get_default_session()
            return

        self._session = sso.get_session(username)

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

    @property
    def authenticated(self) -> bool:
        if self._session.authenticated:
            return True

        return False

    @property
    def session(self):
        return self._session

    @property
    def username(self):
        return self._session.AccountName
