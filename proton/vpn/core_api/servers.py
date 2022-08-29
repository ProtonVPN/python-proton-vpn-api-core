import logging
import random
import time

from proton.vpn.core_api.session import SessionHolder
from proton.vpn.servers import ServerList, VPNServer, CacheHandler
from proton.vpn.servers.enums import ServerFeatureEnum

logger = logging.getLogger(__name__)


class VPNServers:
    FULL_CACHE_EXPIRATION_TIME = 3 * (60 * 60)  # 3h in seconds
    LOADS_CACHE_EXPIRATION_TIME = 15 * 60  # 15min in seconds

    RANDOM_FRACTION = 0.22

    LOGICALS_ROUTE = '/vpn/logicals'
    LOADS_ROUTE = '/vpn/loads'

    """ This implements all the business logic related to ProtonVPN server list.
    """

    def __init__(
            self,
            session_holder: SessionHolder,
            server_list: ServerList = None,
            cache_handler: CacheHandler = None
    ):
        self._session_holder = session_holder
        self._cache_handler = cache_handler or CacheHandler
        self._server_list = server_list

    def get_server_list(self, force_refresh: bool = False):
        if self._server_list is None:
            local_cache = self._cache_handler.load()
            self._server_list = ServerList()

            if local_cache:
                self._update_local_cache(local_cache, True)

            self._update_times_for_next_api_call(True)

        self._update_servers_if_needed(force_refresh)

        return self._server_list

    def _update_servers_if_needed(self, force_refresh):
        fetched_logicals = None

        if self.__next_fetch_logicals < time.time() or force_refresh:
            apidata = self._session_holder.session.api_request(VPNServers.LOGICALS_ROUTE)
            fetched_logicals = True
        elif self.__next_fetch_load < time.time():
            apidata = self._session_holder.session.api_request(VPNServers.LOADS_ROUTE)
            fetched_logicals = False

        if fetched_logicals is not None:
            assert "Code" in apidata
            assert "LogicalServers" in apidata

            self._update_times_for_next_api_call(fetched_logicals)
            self._update_local_cache(apidata, fetched_logicals)

    def _update_local_cache(self, apidata, update_logicals=False):
        if update_logicals:
            self._server_list.update_logical_data(apidata)
        else:
            self._server_list.update_load_data(apidata)

        try:
            self._cache_handler.save(newdata=apidata)
        except Exception as e:
            # This is not fatal, we only were not capable
            # of storing the cache.
            logger.info("Could not save server cache {}".format(e))

    def _update_times_for_next_api_call(self, logicals_data_updated: bool = False):
        if logicals_data_updated:
            full_cache_expiration_time = self.FULL_CACHE_EXPIRATION_TIME * \
                                         self.__generate_random_component()
            self.__next_fetch_logicals = time.time() + full_cache_expiration_time

        loads_cache_expiration_time = self.LOADS_CACHE_EXPIRATION_TIME * \
                                      self.__generate_random_component()
        self.__next_fetch_load = time.time() + loads_cache_expiration_time

    def __generate_random_component(self):
        # 1 +/- 0.22*random
        return 1 + self.RANDOM_FRACTION * (2 * random.random() - 1)

    @property
    def _tier(self):
        return self._session_holder.session.vpn_account.max_tier

    def get_vpn_server_by_name(self, servername: str) -> "VPNServer":
        """
            return an :class:`protonvpn_connection.interfaces.VPNServer` interface from the logical
            name (DE#13) as a entry. Logical name can be secure core logical name also (like CH-FR#1 for ex).
            It can be directly used with :class:`protonvpn_connection.vpnconnection.VPNConnection`
            (after having setup the ports).

            :return: an instance of the default VPNServer
            :rtype: VPNServer
        """
        return self.get_server_list().get_vpn_server(servername)

    def get_server_by_country_code(self, country_code):
        logical_server = self.get_server_list().filter(
            lambda server: server.exit_country.lower() == country_code.lower()
        ).get_fastest_server_in_tier(self._tier)

        return self.get_vpn_server_by_name(logical_server.name)

    def get_fastest_server(self):
        logical_server = self.get_server_list().get_fastest_server_in_tier(self._tier)
        return self.get_vpn_server_by_name(logical_server.name)

    def get_random_server(self):
        logical_server = self.get_server_list().get_random_server_in_tier(self._tier)
        return self.get_vpn_server_by_name(logical_server.name)

    def get_server_with_p2p(self):
        logical_server = self.get_server_list().filter(
            lambda server: ServerFeatureEnum.P2P in server.features and server._tier <= self._tier
        ).sort(lambda server: server.score)[0]

        return self.get_vpn_server_by_name(logical_server.name)

    def get_server_with_streaming(self):
        logical_server = self.get_server_list().filter(
            lambda server: ServerFeatureEnum.STREAMING in server.features and server._tier <= self._tier
        ).sort(lambda server: server.score)[0]

        return self.get_vpn_server_by_name(logical_server.name)

    def get_server_with_tor(self):
        logical_server = self.get_server_list().filter(
            lambda server: ServerFeatureEnum.TOR in server.features and server._tier <= self._tier
        ).sort(lambda server: server.score)[0]

        return self.get_vpn_server_by_name(logical_server.name)

    def get_server_with_secure_core(self):
        logical_server = self.get_server_list().filter(
            lambda server: ServerFeatureEnum.SECURE_CORE in server.features and server._tier <= self._tier
        ).sort(lambda server: server.score)[0]

        return self.get_vpn_server_by_name(logical_server.name)

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
            return self.get_vpn_server_by_name(servername)
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
