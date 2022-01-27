from asyncio.base_events import Server
from proton.session import Session
from proton.vpn.servers import ServerList, CachedServerList
from proton.vpn.servers.exceptions import EmptyServerListError
from proton.vpn.servers.list import ServerFeatureEnum, ServerTierEnum
from proton.vpn.servers.exceptions import ServerFileCacheNotFound, ProtonVPNServerListError
from .country import Country
from typing import Optional
import copy
from enum import Enum


class ServernameServerNotFound(Exception):
    pass


class ProtocolEnum(Enum):
    TCP = "OpenVPN tcp"
    UDP = "OpenVPN udp"
    WIREGUARD = "Wireguard"
    IKEV2 = "ikev2"


class VPNServerConfigChoices(Enum):
    ovpnuserpass = 'ovpnpass'
    ovpncert = 'ovpncert'
    wireguard = 'wg'
    ikev2userpass = 'ikev2pass'
    ikev2cert = 'ikev2cert'

    def __str__(self):
        return self.value


class VPNServer:
    """ Implement :class:`protonvpn_connection.interfaces.VPNServer` to
        provide an interface readily usable to instanciate a :class:`protonvpn.vpnconnection.VPNConnection`
    """
    def __init__(self, entry_ip, udp_ports=None, tcp_ports=None, domain=None, x25519pk=None, servername=None):
        self._entry_ip = entry_ip
        self._udp_ports = udp_ports
        self._tcp_ports = tcp_ports
        self._x25519pk = x25519pk
        self._domain = domain
        self._servername = servername

    @property
    def server_ip(self):
        return self._entry_ip

    @property
    def udp_ports(self):
        return self._udp_ports

    @udp_ports.setter
    def udp_ports(self, ports):
        self._udp_ports = ports

    @property
    def tcp_ports(self):
        return self._tcp_ports

    @tcp_ports.setter
    def tcp_ports(self, ports):
        self._tcp_ports = ports

    @property
    def x25519pk(self):
        return self._x25519pk

    @property
    def domain(self):
        return self._domain

    @property
    def servername(self):
        return self._servername


class VPNServersController:
    LOGICALS_ROUTE = '/vpn/logicals'

    """ This implements all the business logic related to ProtonVPN server list.
    """

    def __init__(self, session: Optional[Session], vpn_tier):
        self._session = session
        self._sl = self._get_cached_server_list()
        self._countries = Country()
        self._vpn_tier = vpn_tier
        self.SUPPORTED_FEATURES = {
            ServerFeatureEnum.NORMAL: "",
            ServerFeatureEnum.SECURE_CORE: "Secure-Core",
            ServerFeatureEnum.TOR: "Tor",
            ServerFeatureEnum.P2P: "P2P",
            ServerFeatureEnum.STREAMING: "Streaming",
            ServerFeatureEnum.IPv6: "IPv6"
        }
        self.SERVER_TIERS = {
            ServerTierEnum.FREE: "Free",
            ServerTierEnum.BASIC: "Basic",
            ServerTierEnum.PLUS_VISIONARY: "Plus/Visionary",
            ServerTierEnum.PM: "PMTEAM"
        }

    def get_logicals(self) -> dict:
        return self._session.api_request(VPNServersController.LOGICALS_ROUTE)

    def _get_cached_server_list(self) -> CachedServerList:
        try:
            sl = CachedServerList()
        except ServerFileCacheNotFound:
            sl = CachedServerList(self.get_logicals())
        return sl

    @property
    def vpn_tier(self):
        return self._vpn_tier

    def get_servers_per_country(self):
        return self._countries.get_dict_with_country_servername(self._sl, self.vpn_tier)

    def get_protocol_name_choices(self):
        return [
                (ProtocolEnum.UDP.value, "OpenVPN UDP"),
                (ProtocolEnum.TCP.value, "OpenVPN TCP"),
                (ProtocolEnum.WIREGUARD.value, "Wireguard")
                ]

    def get_countries_name_choices(self, countries):
        choices = []
        for country in sorted(countries.keys()):
            try:
                country_code = [
                    cc for
                    cc, name in self._countries.country_codes.items()
                    if name == country
                ].pop()
            except IndexError:
                country_code = 'XX'
            choices.append((country_code, f"{country}"))
        return choices

    def get_securecore_countries_name_choices(self):
        choices = []
        country_codes = set()
        s = self._sl.get_secure_core_servers()
        for server in s:
            country_codes.add(server.exit_country)

        for country_code in country_codes:
            country_name = self._countries.extract_country_name(country_code)
            choices.append((country_code, f"{country_name}"))

        choices.sort(key=lambda x: x[1])
        return choices

    def get_securecore_countries_per_entry_country_choices(self, servers):
        choices = []
        country_codes = set()
        for server in servers:
            country_codes.add(server.entry_country)

        for country_code in country_codes:
            country_name = self._countries.extract_country_name(country_code)
            choices.append((country_code, f"{country_name}"))

        choices.sort(key=lambda x: x[1])
        return choices

    def get_securecore_server_choices(self, exit_country, entry_country=None):
        s = self._sl.get_secure_core_servers()
        if entry_country is None:
            s_country = list(filter(lambda server: server.exit_country == exit_country, s))
        else:
            s_country = list(
                filter(
                    lambda server: (
                        server.exit_country == exit_country
                        and server.entry_country == entry_country
                        ),
                    s
                )
            )
        return s_country

    def get_servers_choices(self, country, countries):
        """Displays a dialog with a list of servers.

        Args:
            countries (dict): {country_code: servername}
            country (string): country code (PT, SE, DK, etc)
        Returns:
            string: servername (PT#8, SE#5, DK#10, etc)
        """
        choices = []

        country_servers = self.sort_servers(country, countries)
        for servername in country_servers:
            server = self.config_for_server_with_servername(servername)
            load = str(int(server.load)).rjust(3, " ")
            _features = copy.copy(server.features)
            try:
                _features.pop(ServerFeatureEnum.NORMAL)
            except IndexError:
                pass

            if len(_features) > 1:
                features = ", ".join(
                    [self.SUPPORTED_FEATURES[feature] for feature in _features]
                )
            elif len(_features) == 1:
                features = self.SUPPORTED_FEATURES[_features[0]]
            else:
                features = ""

            tier = self.SERVER_TIERS[ServerTierEnum(server.tier)]

            choices.append(
                (
                    servername, "Load: {0}% | {1} | {2}".format(
                        load, tier, features
                    )
                )
            )
        return choices

    def config_for_server_with_servername(self, servername):
        """Select server by servername.

        Returns:
            LogicalServer
        """
        try:
            return self._sl.filter(
                lambda server:
                server.tier <= self.vpn_tier
                and server.name.lower() == servername.lower() # noqa
            ).get_fastest_server(self.vpn_tier)
        except EmptyServerListError:
            raise ServernameServerNotFound(
                "The specified servername could not be found.\n"
                "Either the server went into maintenance or "
                "you don't have access to the server with your plan."
            )

    def sort_servers(self, country, countries):
        country_servers = countries[self._countries.extract_country_name(country)]

        non_match_tier_servers = {}
        match_tier_servers = {}
        user_tier = self.vpn_tier

        for server in country_servers:
            try:
                _server = self.config_for_server_with_servername(server)
            except ServernameServerNotFound:
                continue

            server_tier = _server.tier

            if server_tier == user_tier:
                match_tier_servers[server] = server_tier
            elif (
                (server_tier > user_tier or server_tier < user_tier)
                and not server_tier == 3
            ):
                non_match_tier_servers[server] = server_tier

        sorted_dict = dict(
            sorted(
                non_match_tier_servers.items(),
                key=lambda s: s[1],
                reverse=True
            )
        )
        match_tier_servers.update(sorted_dict)
        return [
            servername
            for servername, server_tier
            in match_tier_servers.items()
        ]

    def get_vpn_server(self, logical: str) -> VPNServer:
        """
            return an :class:`protonvpn_connection.interfaces.VPNServer` interface from the logical name (DE#13) as a entry. Logical
            name can be secure core logical name also (like CH-FR#1 for ex). It can be directly used
            with :class:`protonvpn_connection.vpnconnection.VPNConnection` (after having setup the ports). Th

            :return: an instance of the default VPNServer
            :rtype: VPNServer
        """
        try:
            server = list(filter(lambda server: server.name == logical, self._sl))[0]
            physical = server.get_random_physical_server()
            self._sl.match_server_domain(physical)
            ip = physical.entry_ip
            domain = physical.domain
            # FIXME : This is required for wireguard
            wg_server_pk = server.physical_servers[0].x25519_pk
        except (ProtonVPNServerListError, IndexError):
            raise

        return VPNServer(ip, domain=domain, x25519pk=wg_server_pk, servername=logical)

    @staticmethod
    def get_protocol_choices():
        return [
            (VPNServerConfigChoices.ovpncert.value, "OpenVPN Cert auth"),
            (VPNServerConfigChoices.ovpnuserpass.value, "OpenVPN User pass auth"),
            (VPNServerConfigChoices.ikev2cert.value, "IKEv2 Cert auth"),
            (VPNServerConfigChoices.ikev2userpass.value, "IKEv2 user pass auth"),
            (VPNServerConfigChoices.wireguard.value, "Wireguard")
        ]
