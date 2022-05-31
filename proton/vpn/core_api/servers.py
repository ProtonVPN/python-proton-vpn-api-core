import logging

from proton.vpn.servers import CachedServerList
from proton.vpn.servers import ServerFeatureEnum
from proton.vpn.servers.exceptions import ServerFileCacheNotFound
from proton.vpn.servers.list import VPNServer

from proton.vpn.core_api.session import SessionHolder


logger = logging.getLogger(__name__)


class VPNServers:
    LOGICALS_ROUTE = '/vpn/logicals'

    """ This implements all the business logic related to ProtonVPN server list.
    """

    def __init__(self, session_holder: SessionHolder, cached_server_list: CachedServerList = None):
        self._session_holder = session_holder
        self._sl = cached_server_list

    @property
    def list(self):
        if self._sl:
            return self._sl

        try:
            self._sl = CachedServerList()
            return self._sl
        except ServerFileCacheNotFound:
            logger.debug("Server list cache not found.")

        servers = self._session_holder.session.api_request(self.LOGICALS_ROUTE)
        self._sl = CachedServerList(servers)
        return self._sl

    @property
    def tier(self):
        return self._session_holder.session.vpn_account.max_tier

    def get_fastest_server(self):
        logical_server = self.list.get_fastest_server(self.tier)
        return self._get_vpn_server(logical_server.name)

    def get_random_server(self):
        logical_server = self.list.get_random_server(self.tier)
        return self._get_vpn_server(logical_server.name)

    def get_server_by_country_code(self, country_code):
        logical_server = self.list.filter(
            lambda server: server.exit_country.lower() == country_code.lower()
        ).get_fastest_server(self.tier)

        return self._get_vpn_server(logical_server.name)

    def get_server_with_p2p(self):
        logical_server = self.list.filter(
            lambda server: ServerFeatureEnum.P2P in server.features and server.tier <= self.tier
        ).sort(lambda server: server.score)[0]

        return self._get_vpn_server(logical_server.name)

    def get_server_with_tor(self):
        logical_server = self.list.filter(
            lambda server: ServerFeatureEnum.TOR in server.features and server.tier <= self.tier
        ).sort(lambda server: server.score)[0]

        return self._get_vpn_server(logical_server.name)

    def get_server_with_secure_core(self):
        logical_server = self.list.filter(
            lambda server: ServerFeatureEnum.SECURE_CORE in server.features and server.tier <= self.tier
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

    def _get_vpn_server(self, logical: str) -> VPNServer:
        """
            return an :class:`protonvpn_connection.interfaces.VPNServer` interface from the logical name (DE#13) as a entry. Logical
            name can be secure core logical name also (like CH-FR#1 for ex). It can be directly used
            with :class:`protonvpn_connection.vpnconnection.VPNConnection` (after having setup the ports). Th

            :return: an instance of the default VPNServer
            :rtype: VPNServer
        """
        return self.list.get_vpn_server(logical)
