class Application:

    def __init__(self, view, session_orchestrator=None, connection_orchestrator=None):
        self._view = view
        if not session_orchestrator:
            from .orchestrators import VPNSessionOrchestrator
            self._session_orchestrator = VPNSessionOrchestrator(self._view)
        else:
            self._session_orchestrator = session_orchestrator

        if not connection_orchestrator:
            from .orchestrators import VPNConnectionOrchestrator
            self._connection_orchestrator = VPNConnectionOrchestrator(self._view, self._session_orchestrator)
        else:
            self._connection_orchestrator = connection_orchestrator

    def login(self, username):
        return self._session_orchestrator.login(username)

    def logout(self):
        return self._session_orchestrator.logout()

    def authenticated(self) -> bool:
        return self._session_orchestrator.authenticated

    def connect(self, protocol=None, **kwargs):
        _protocol = protocol
        # if not _protocol:
        # from user settings fetch protocol
        self._connection_orchestrator.setup(_protocol)
        self._connection_orchestrator.connect(**kwargs)

    def disconnect(self):
        self._connection_orchestrator.disconnect()
