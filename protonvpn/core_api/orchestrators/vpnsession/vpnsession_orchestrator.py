class VPNSessionOrchestrator:
    def __init__(self, view, username=None, session_controller=None, vpn_credentials_controller=None):
        self._view = view
        self._vpnsession_ctrl = None
        self._vpncred_ctrl = None

        if (username or not username) and not session_controller and not vpn_credentials_controller:
            from protonvpn.core_api.controllers.vpnsession import VPNSessionController
            self._vpnsession_ctrl = VPNSessionController(username)

            from protonvpn.core_api.controllers.vpncredentials import VPNCredentialController
            self._vpncred_ctrl = VPNCredentialController(self._vpnsession_ctrl.username)

        elif not username and session_controller and vpn_credentials_controller:
            self._vpnsession_ctrl = session_controller
            self._vpncred_ctrl = vpn_credentials_controller
        else:
            raise RuntimeError("Either provide controllers or username, but not both")

    def login(self, username, cert_duration=1440) -> bool:
        if self.authenticated:
            self._view.display_info('You are already logged in')
            return True
        else:
            password = self._view.ask_for_login()

        if self._vpnsession_ctrl.login(username, password):
            from protonvpn.core_api.controllers.vpncredentials import VPNCredentialController
            from proton.session.exceptions import ProtonAPI2FANeeded

            try:
                self._vpncred_ctrl = VPNCredentialController(
                    self._vpnsession_ctrl.username, cert_duration
                )
                self._refresh()
                self._view.display_info('login successfull')
                return True
            except ProtonAPI2FANeeded:
                self._view.display_info('2FA needed')
                auth2fatoken = self._view.ask_for_2fa()

                if self._vpnsession_ctrl.set2fa(auth2fatoken):
                    self._refresh()
                    self._view.display_info('login successfull')
                    return True

            self._vpnsession_ctrl.logout()
            return False

        self._view.display_info('wrong password')
        return False

    def logout(self) -> bool:
        if self.authenticated:
            self._vpncred_ctrl.vpnaccount.clear()
            self._vpnsession_ctrl.logout()
            self._view.display_info('logged out')
            return True

        self._view.display_info('you are already logged out')
        return False

    def _refresh(self):
        self._vpncred_ctrl.refresh_vpn_credentials()

    def set2fa(self, code: str) -> bool:
        if self._session.provide_2fa(code):
            return True

        return False

    @property
    def authenticated(self) -> bool:
        try:
            if self._vpnsession_ctrl.authenticated:
                return True
        except AttributeError:
            pass

        return False

    @property
    def vpnsession_ctrl(self):
        return self._vpnsession_ctrl

    @property
    def username(self):
        return self._vpnsession_ctrl.username

    @property
    def tier(self):
        return self._vpncred_ctrl.vpnaccount.max_tier

    @property
    def credentials(self):
        return self._vpncred_ctrl.vpnaccount.get_credentials()
