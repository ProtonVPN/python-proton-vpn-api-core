class VPNConnectionOrchestrator:

    def __init__(
        self,
        view,
        session_orchestrator,
        vpnconnection_ctrl=None,
        vpnservers_controller=None
    ):
        self._view = view
        self._session_orchestrator = session_orchestrator

        if not vpnconnection_ctrl:
            from protonvpn.core_api.controllers import VPNConnectionController
            self._vpnconnection_ctrl = VPNConnectionController()
        else:
            self._vpnconnection_ctrl = vpnconnection_ctrl

        if not vpnservers_controller:
            from protonvpn.core_api.controllers import VPNServersController
            self._vpnserver_ctlr = VPNServersController(
                self._session_orchestrator.session,
                self._session_orchestrator.tier,
            )
        else:
            self._vpnserver_ctlr = vpnservers_controller

    def setup(self, protocol, backend=None):
        self._vpnconnection_ctrl.setup(protocol, backend)

    def connect(self, servername: str, settings=None):
        vpnserver = self._get_server_by_name(servername)
        if not vpnserver:
            return

        vpnserver.tcp_ports = [443, 5995, 8443, 5060]
        vpnserver.udp_ports = [80, 443, 4569, 1194, 5060, 51820]

        self._vpnconnection_ctrl.connect(
            vpnserver,
            self._session_orchestrator._account,
            settings
        )
        self._view.display_info(
            "Connected to {} with".format(vpnserver.servername)
        )

    def disconnect(self):
        self._vpnconnection_ctrl.disconnect()
        self._view.display_info("Disconnected")

    def _get_server_by_name(self, servername: str):
        try:
            return self._vpnserver_ctlr.get_vpn_server(servername)
        except IndexError:
            self._view.display_info(
                "Could not find server {}".format(servername)
            )
            return False
