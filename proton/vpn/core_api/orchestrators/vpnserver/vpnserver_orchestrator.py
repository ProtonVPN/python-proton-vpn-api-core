class VPNServerOrchestrator:

    def __init__(self, vpnsession_orchestrator, vpnserver_ctrl=None):

        self._vpnsession_orchestrator = vpnsession_orchestrator

        if not vpnserver_ctrl:
            from ...controllers.vpnservers import VPNServersController
            self._vpnserver_ctlr = VPNServersController(
                self._vpnsession_orchestrator
            )
        else:
            self._vpnserver_ctlr = vpnserver_ctrl

    def get_server(self, **kwargs_feature):
        return self._vpnserver_ctlr.get_server_with_features(**kwargs_feature)
