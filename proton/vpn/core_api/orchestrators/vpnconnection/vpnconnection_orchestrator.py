class VPNConnectionOrchestrator:

    def __init__(
        self,
        view,
        session_orchestrator,
        usersettings_orchestrator=None,
        vpnconnection_ctrl=None,
        vpnservers_orchestrator=None
    ):
        self._view = view
        self._session_orchestrator = session_orchestrator
        self._usersettings_orchestrator = usersettings_orchestrator

        if not vpnconnection_ctrl:
            from proton.vpn.core_api.controllers import VPNConnectionController
            self._vpnconnection_ctrl = VPNConnectionController()
        else:
            self._vpnconnection_ctrl = vpnconnection_ctrl

        if not vpnservers_orchestrator:
            from ..vpnserver import VPNServerOrchestrator
            self._vpnservers_orchestrator = VPNServerOrchestrator(
                self._session_orchestrator
            )
        else:
            self._vpnservers_orchestrator = vpnservers_orchestrator

    def setup(self, protocol, backend=None):
        self._vpnconnection_ctrl.setup(protocol, backend)

    def connect(self, **kwargs):
        vpnserver = self._vpnservers_orchestrator.get_server(**kwargs)
        if not vpnserver:
            self._view.display_error("Could not find server with provided arguments")
            return

        vpnserver.tcp_ports = [443, 5995, 8443, 5060]
        vpnserver.udp_ports = [80, 443, 4569, 1194, 5060, 51820]

        self._vpnconnection_ctrl.connect(
            vpnserver,
            self._session_orchestrator.credentials,
            self._usersettings_orchestrator.get_vpn_settings()
        )
        self._view.display_info(
            "Connected to {} with".format(vpnserver.servername)
        )

    def disconnect(self):
        self._vpnconnection_ctrl.disconnect()
        self._view.display_info("Disconnected")
