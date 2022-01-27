
class Application:

    def __init__(self, view, session_orchestrator=None):
        self._view = view
        if not session_orchestrator:
            from .orchestrators import VPNSessionOrchestrator
            session_orchestrator = VPNSessionOrchestrator(self._view)

        self._session_orchestrator = session_orchestrator

    def login(self, username):
        return self._session_orchestrator.login(username)

    def logout(self):
        return self._session_orchestrator.logout()

    def authenticated(self) -> bool:
        return self._session_orchestrator.authenticated
