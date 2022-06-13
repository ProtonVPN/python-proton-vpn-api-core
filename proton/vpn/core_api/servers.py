import logging
import random
import time

from proton.vpn.core_api.session import SessionHolder
from proton.vpn.servers import ServerList
from proton.vpn.servers.enums import ServerFeatureEnum
from proton.vpn.servers.list import VPNServer

logger = logging.getLogger(__name__)


class VPNServers:
    FULL_CACHE_TIME_EXPIRE = 3 * (60 * 60)  # 3h in seconds
    LOADS_CACHE_TIME_EXPIRE = 15 * 60  # 15min in seconds

    RANDOM_FRACTION = 0.22

    LOGICALS_ROUTE = '/vpn/logicals'
    LOADS_ROUTE = '/vpn/loads'

    """ This implements all the business logic related to ProtonVPN server list.
    """

    def __init__(self, session_holder: SessionHolder, server_list: ServerList = None):
        self._session_holder = session_holder
        self.__server_list = server_list

    def get_server_list(self, force_refresh: bool = False):
        if self.__server_list is None:
            self.__server_list = ServerList()

            try:
                self.__server_list.import_from_cache()
            except FileNotFoundError as e:
                raise Exception("Server list cache file not found, please save") from e

            self._update_times_for_next_api_call()

        self._update_servers_if_needed(force_refresh)

        return self.__server_list

    def _update_servers_if_needed(self, force_refresh):
        logicals_data_updated = False
        loads_data_updated = False

        if self.__next_fetch_logicals < time.time() or force_refresh:
            # Update logicals
            self.__server_list.update_logical_data(self._session_holder.session.api_request(VPNServers.LOGICALS_ROUTE))
            logicals_data_updated = True
        elif self.__next_fetch_load < time.time() or force_refresh:
            # Update loads
            self.__server_list.update_load_data(self._session_holder.session.api_request(VPNServers.LOADS_ROUTE))
            loads_data_updated = True

        if any([logicals_data_updated, loads_data_updated]):
            self._update_times_for_next_api_call(logicals_data_updated)

            try:
                self.__server_list.export_to_cache()
            except Exception as e:
                # This is not fatal, we only were not capable
                # of storing the cache.
                logger.info("Could not save server cache {}".format(e))

    def _update_times_for_next_api_call(self, logicals_data_updated: bool = False):
        if logicals_data_updated:
            self.__next_fetch_logicals = self \
                .logicals_update_timestamp.logicals_update_timestamp + \
                self.FULL_CACHE_TIME_EXPIRE * self.__generate_random_component()

        self.__next_fetch_load = self \
            .logicals_update_timestamp.loads_update_timestamp + \
            self.LOADS_CACHE_TIME_EXPIRE * self.__generate_random_component()

    def __generate_random_component(self):
        # 1 +/- 0.22*random
        return (1 + self.RANDOM_FRACTION * (2 * random.random() - 1))

    @property
    def tier(self):
        return self._session_holder.session.vpn_account.max_tier

    def get_server_from_name(self, servername: str) -> "VPNServer":
        """
            return an :class:`protonvpn_connection.interfaces.VPNServer` interface from the logical
            name (DE#13) as a entry. Logical name can be secure core logical name also (like CH-FR#1 for ex).
            It can be directly used with :class:`protonvpn_connection.vpnconnection.VPNConnection`
            (after having setup the ports).

            :return: an instance of the default VPNServer
            :rtype: VPNServer
        """
        return self.server_list.get_vpn_server(servername)

    def get_server_from_country_code(self, country_code):
        logical_server = self.server_list.filter(
            lambda server: server.exit_country.lower() == country_code.lower()
        ).get_fastest_server(self.tier)

        return self.get_vpn_server_from_name(logical_server.name)

    def get_fastest_server(self):
        logical_server = self.server_list.get_fastest_server(self.tier)
        return self.get_vpn_server_from_name(logical_server.name)

    def get_random_server(self):
        logical_server = self.server_list.get_random_server(self.tier)
        return self.get_vpn_server_from_name(logical_server.name)

    def get_server_with_p2p(self):
        logical_server = self.server_list.filter(
            lambda server: ServerFeatureEnum.P2P in server.features and server.tier <= self.tier
        ).sort(lambda server: server.score)[0]

        return self.get_vpn_server_from_name(logical_server.name)

    def get_server_with_streaming(self):
        logical_server = self.server_list.filter(
            lambda server: ServerFeatureEnum.STREAMING in server.features and server.tier <= self.tier
        ).sort(lambda server: server.score)[0]

        return self.get_vpn_server_from_name(logical_server.name)

    def get_server_with_tor(self):
        logical_server = self.server_list.filter(
            lambda server: ServerFeatureEnum.TOR in server.features and server.tier <= self.tier
        ).sort(lambda server: server.score)[0]

        return self.get_vpn_server_from_name(logical_server.name)

    def get_server_with_secure_core(self):
        logical_server = self.server_list.filter(
            lambda server: ServerFeatureEnum.SECURE_CORE in server.features and server.tier <= self.tier
        ).sort(lambda server: server.score)[0]

        return self.get_vpn_server_from_name(logical_server.name)
