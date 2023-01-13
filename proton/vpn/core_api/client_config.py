"""
Client Config module.
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import List
import time

DEFAULT_CLIENT_CONFIG = {
    "OpenVPNConfig": {
        "DefaultPorts": {
            "UDP": [80, 51820, 4569, 1194, 5060],
            "TCP": [443, 7770, 8443]
        }
    },
    "HolesIPs": ["62.112.9.168", "104.245.144.186"],
    "ServerRefreshInterval": 10,
    "FeatureFlags": {
        "NetShield": 0,
        "GuestHoles": 0,
        "ServerRefresh": 1,
        "StreamingServicesLogos": 1,
        "PortForwarding": 0,
        "ModerateNAT": 1,
        "SafeMode": 0,
        "StartConnectOnBoot": 1,
        "PollNotificationAPI": 1,
        "VpnAccelerator": 1,
        "SmartReconnect": 1,
        "PromoCode": 0,
        "WireGuardTls": 1
    },
    "CacheExpiration": time.time() - 60 * 3
}


@dataclass
class OpenVPNPorts:
    """Dataclass for openvpn ports.
    These ports are mainly used for establishing VPN connections.
    """
    udp: List
    tcp: List

    @staticmethod
    def from_dict(openvpn_ports: dict) -> OpenVPNPorts:
        """Creates OpenVPNPorts object from data."""
        # The lists are copied to avoid side effects if the dict is modified.
        return OpenVPNPorts(
            openvpn_ports["UDP"].copy(),
            openvpn_ports["TCP"].copy()
        )


@dataclass
class FeatureFlags:  # pylint: disable=R0902
    """Dataclass for feature flags ports.

    Flags are important since they can let us know which feature are enabled
    or disabled. Also certain feature flags dependent on user tier.
    """
    netshield: bool
    guest_holes: bool
    server_refresh: bool
    streaming_services_logos: bool
    port_forwarding: bool
    moderate_nat: bool
    safe_mode: bool
    start_connect_on_boot: bool
    poll_notification_api: bool
    vpn_accelerator: bool
    smart_reconnect: bool
    promo_code: bool
    wireguard_tls: bool

    @staticmethod
    def from_dict(feature_flags: dict) -> FeatureFlags:
        """Creates FeatureFlags object from data."""
        return FeatureFlags(
            feature_flags["NetShield"],
            feature_flags["GuestHoles"],
            feature_flags["ServerRefresh"],
            feature_flags["StreamingServicesLogos"],
            feature_flags["PortForwarding"],
            feature_flags["ModerateNAT"],
            feature_flags["SafeMode"],
            feature_flags["StartConnectOnBoot"],
            feature_flags["PollNotificationAPI"],
            feature_flags["VpnAccelerator"],
            feature_flags["SmartReconnect"],
            feature_flags["PromoCode"],
            feature_flags["WireGuardTls"]
        )


class ClientConfig:
    """Holds the main structure for obtaining various types of information.
    """
    def __init__(
        self, openvpn_ports, holes_ips,
        server_refresh_interval, feature_flags,
        cache_expiration
    ):  # pylint: disable=R0913
        self.openvpn_ports = openvpn_ports
        self.holes_ips = holes_ips
        self.server_refresh_interval = server_refresh_interval
        self.feature_flags = feature_flags
        self.cache_expiration = cache_expiration

    @staticmethod
    def from_dict(apidata: dict) -> ClientConfig:
        """Creates ClientConfig object from data."""
        openvpn_ports = apidata["OpenVPNConfig"]["DefaultPorts"]
        holes_ips = apidata["HolesIPs"]
        server_refresh_interval = apidata["ServerRefreshInterval"]
        feature_flags = apidata["FeatureFlags"]
        cache_expiration = apidata["CacheExpiration"]

        return ClientConfig(
            # No need to copy openvpn_ports, OpenVPNPorts takes care of it.
            OpenVPNPorts.from_dict(openvpn_ports),
            # We copy the holes_ips list to avoid side effects if it's modified.
            holes_ips.copy(),
            server_refresh_interval,
            FeatureFlags.from_dict(feature_flags),
            cache_expiration
        )

    @staticmethod
    def default() -> ClientConfig:
        """":returns: the default client configuration."""
        return ClientConfig.from_dict(DEFAULT_CLIENT_CONFIG)

    @property
    def is_expired(self) -> bool:
        """Returns if data has expired"""
        current_time = time.time()
        return current_time > self.cache_expiration
