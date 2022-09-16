import os

from proton.utils import ExecutionEnvironment

from proton.vpn.core_api.connection import VPNConnectionHolder
from proton.vpn.core_api.servers import VPNServers
from proton.vpn.core_api.settings import BasicSettings
from proton.vpn.core_api.session import SessionHolder
from proton.vpn.session.dataclasses import LoginResult
from proton.vpn.core_api.exceptions import VPNConnectionFoundAtLogout
from proton.vpn.core_api.logger import logger


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

    def is_user_logged_in(self) -> bool:
        return self._session_holder.session.logged_in

    def logout(self):
        if self.connection.get_current_connection():
            raise VPNConnectionFoundAtLogout("Active connection was found")

        self._session_holder.session.logout()
