import os

from proton.utils import ExecutionEnvironment

from proton.vpn.core_api.connection import VPNConnectionHolder
from proton.vpn.core_api.settings import BasicSettings
from proton.vpn.core_api.session import SessionHolder, LoginResult


class ProtonVPNAPI:
    def __init__(self):
        self.session_holder = SessionHolder()
        self.settings = BasicSettings(
            os.path.join(ExecutionEnvironment().path_config, "settings.json")
        )
        self.connection_holder = VPNConnectionHolder(self.session_holder, self.settings)

    @property
    def session(self):
        return self.session_holder.session

    def login(self, username: str, password: str) -> LoginResult:
        return self.session_holder.get_session_for(username).login(username, password)

    def submit_2fa_code(self, code: str) -> LoginResult:
        return self.session.provide_2fa(code)

    def logout(self):
        self.session.logout()

    def register(self, subscriber):
        self.connection_holder.register(subscriber)

    def unregister(self, subscriber):
        self.connection_holder.unregister(subscriber)

    def connect(self, protocol: str = None, backend: str = None, **kwargs):
        self.connection_holder.connect(protocol, backend, **kwargs)

    def disconnect(self):
        self.connection_holder.disconnect()
