from asyncio.base_events import Server
from proton.session import Session
from proton.vpn.servers import ServerList, CachedServerList
from proton.vpn.servers.exceptions import EmptyServerListError
from proton.vpn.servers.list import ServerFeatureEnum, ServerTierEnum
from proton.vpn.servers.exceptions import ServerFileCacheNotFound, ProtonVPNServerListError
from .country import Country
from typing import Optional


class ServernameServerNotFound(Exception):
    pass


class VPNServersController:
    LOGICALS_ROUTE = '/vpn/logicals'

    """ This implements all the business logic related to ProtonVPN server list.
    """

    def __init__(
        self,
        session_orchestrator: Optional["VPNSessionOrchestrator"],
        cached_serverlist=None
    ):
        self._session_orchestrator = session_orchestrator

        if not cached_serverlist:
            self._sl = self._get_cached_server_list()
        else:
            self._sl = cached_serverlist

    def _get_cached_server_list(self) -> "CachedServerList":
        from protonvpn.servers import CachedServerList
        from protonvpn.servers.exceptions import ServerFileCacheNotFound

        try:
            sl = CachedServerList()
        except ServerFileCacheNotFound:
            sl = CachedServerList(
                self._session_orchestrator.vpnsession_ctrl.vpn_logicals
            )
        return sl

    def get_fastest_server(self):
        logical_server = self._sl.get_fastest_server(
            self._session_orchestrator.tier
        )
        return self._get_vpn_server(logical_server.name)

    def get_random_server(self):
        logical_server = self._sl.get_random_server(
            self._session_orchestrator.tier
        )
        return self._get_vpn_server(logical_server.name)

    def get_server_by_country_code(self, country_code):
        logical_server = self._sl.filter(
            lambda server: server.exit_country.lower() == country_code.lower()
        ).get_fastest_server(self._session_orchestrator.tier)

        return self._get_vpn_server(logical_server.name)

    def get_server_with_p2p(self):
        from protonvpn.servers import ServerFeatureEnum
        logical_server = self._sl.filter(
            lambda server: ServerFeatureEnum.P2P in server.features
            and server.tier <= self._session_orchestrator.tier
        ).sort(lambda server: server.score)[0]

        return self._get_vpn_server(logical_server.name)

    def get_server_with_tor(self):
        from protonvpn.servers import ServerFeatureEnum
        logical_server = self._sl.filter(
            lambda server: ServerFeatureEnum.TOR in server.features
            and server.tier <= self._session_orchestrator.tier
        ).sort(lambda server: server.score)[0]

        return self._get_vpn_server(logical_server.name)

    def get_server_with_secure_core(self):
        from protonvpn.servers import ServerFeatureEnum
        logical_server = self._sl.filter(
            lambda server: ServerFeatureEnum.SECURE_CORE in server.features
            and server.tier <= self._session_orchestrator.tier
        ).sort(lambda server: server.score)[0]

        return self._get_vpn_server(logical_server.name)

    def get_server_with_features(self, **kwargs_feature):
        servername = kwargs_feature.get("servername")
        fastest = kwargs_feature.get("fastest")
        random = kwargs_feature.get("random")
        country_code = kwargs_feature.get("country_code")

        p2p = kwargs_feature.get("p2p")
        tor = kwargs_feature.get("tor")
        secure_core = kwargs_feature.get("secure_core")

        servername = servername if servername and servername != "None" else None

        if servername:
            return self._get_vpn_server(servername)
        elif fastest:
            return self.get_fastest_server()
        elif random:
            return self.get_random_server()
        elif country_code:
            return self.get_server_by_country_code(country_code)
        elif p2p:
           return self.get_server_with_p2p()
        elif tor:
            return self.get_server_with_tor()
        elif secure_core:
            return self.get_server_with_secure_core()

    def _get_vpn_server(self, logical: str) -> "VPNServer":
        """
            return an :class:`protonvpn_connection.interfaces.VPNServer` interface from the logical name (DE#13) as a entry. Logical
            name can be secure core logical name also (like CH-FR#1 for ex). It can be directly used
            with :class:`protonvpn_connection.vpnconnection.VPNConnection` (after having setup the ports). Th

            :return: an instance of the default VPNServer
            :rtype: VPNServer
        """
        return self._sl.get_vpn_server(logical)
