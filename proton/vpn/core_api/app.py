class Application:

    def __init__(self, view, session_orchestrator=None, connection_orchestrator=None, usersettings_orchestrator=None):
        self._view = view
        if not session_orchestrator:
            from .orchestrators import VPNSessionOrchestrator
            self._session_orchestrator = VPNSessionOrchestrator(self._view)
        else:
            self._session_orchestrator = session_orchestrator

        if not usersettings_orchestrator:
            from .orchestrators import UserSettingsOrchestrator
            self._settings_orchestrator = UserSettingsOrchestrator()
        else:
            self._settings_orchestrator = usersettings_orchestrator

        if not connection_orchestrator:
            from .orchestrators import VPNConnectionOrchestrator
            self._connection_orchestrator = VPNConnectionOrchestrator(
                self._view, self._session_orchestrator,
                self._settings_orchestrator
            )
        else:
            self._connection_orchestrator = connection_orchestrator

    def login(self, username):
        return self._session_orchestrator.login(username)

    def logout(self):
        return self._session_orchestrator.logout()

    def connect(self, protocol=None, **kwargs):
        _protocol = protocol
        if not protocol:
            _protocol = self._session_orchestrator.protocol.value

        self._connection_orchestrator.setup(_protocol)
        self._connection_orchestrator.connect(**kwargs)

    def disconnect(self):
        self._connection_orchestrator.disconnect()

    @property
    def authenticated(self) -> bool:
        return self._session_orchestrator.authenticated

    @property
    def settings(self):
        return self._settings_orchestrator
