import os

from proton.utils import ExecutionEnvironment

from proton.vpn.core_api.connection import VPNConnectionHolder
from proton.vpn.core_api.servers import VPNServers
from proton.vpn.core_api.settings import BasicSettings
from proton.vpn.core_api.session import SessionHolder, LoginResult


class ProtonVPNAPI:
    def __init__(self):
        self._session_holder = SessionHolder()
        self.settings = BasicSettings(
            os.path.join(ExecutionEnvironment().path_config, "settings.json")
        )
        self.connection = VPNConnectionHolder(self._session_holder, self.settings)
        self.servers = VPNServers(self._session_holder)

    def login(self, username: str, password: str) -> LoginResult:
        return self._session_holder.get_session_for(username).login(username, password)

    def submit_2fa_code(self, code: str) -> LoginResult:
        return self._session_holder.session.provide_2fa(code)

    def logout(self):
        self._session_holder.session.logout()
