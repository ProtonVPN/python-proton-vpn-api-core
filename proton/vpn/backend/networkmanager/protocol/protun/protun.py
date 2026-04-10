"""
Protun protocol implementation.


Copyright (c) 2026 Proton AG

This file is part of Proton VPN.

Proton VPN is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Proton VPN is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with ProtonVPN.  If not, see <https://www.gnu.org/licenses/>.
"""
# pylint: disable=R0801 # Duplicate code with wireguard.py and openvpn.py but that's expected for now.

from __future__ import annotations

import json
import socket
import uuid
import logging
from concurrent.futures import Future
from getpass import getuser
from ipaddress import IPv4Address, IPv6Address
from typing import Dict, Optional, Union, List

import gi

gi.require_version("NM", "1.0")  # noqa: required before importing NM module
# pylint: disable=wrong-import-position
from gi.repository import NM

from proton.vpn.connection import events, states
from proton.vpn.connection.events import EventContext
from proton.vpn.connection.interfaces import Settings
from proton.vpn.backend.networkmanager.core import LinuxNetworkManager, LocalAgentMixin


logger = logging.getLogger(__name__)

SERVICE_TYPE = "org.freedesktop.NetworkManager.protun"
STORE_PRIVATE_KEY_IN_KEYRING = "1"
PRIVATE_KEY = "private-key"
PRIVATE_KEY_FLAGS = "private-key-flags"

# Internal network configuration — same WireGuard infrastructure as wireguard.py
_INTERNAL_IPV4_ADDRESS = "10.2.0.2"
_INTERNAL_IPV4_PREFIX = 32
_INTERNAL_IPV4_DNS = "10.2.0.1"
_INTERNAL_IPV4_DNS_SEARCH = "~"
_DNS_PRIORITY = -1500


class Protun(LinuxNetworkManager, LocalAgentMixin):
    """Creates a protun VPN plugin connection."""

    SIGNAL_NAME: str = "vpn-state-changed"
    VIRTUAL_DEVICE_NAME: str = "proton0"
    PLUGIN_NAME: str = "protun"
    connection: Optional[NM.SimpleConnection] = None
    plugin_exists: Optional[bool] = None

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        LocalAgentMixin.__init__(self)
        self._connection_settings = None

    def setup(self) -> Future:
        """Creates and registers the NM VPN connection."""
        self._generate_connection()
        self._modify_connection()
        return self.nm_client.add_connection_async(self.connection)

    def _generate_connection(self):
        self._unique_id = str(uuid.uuid4())
        self._connection_settings = NM.SettingConnection.new()
        self.connection = NM.SimpleConnection.new()

    def _modify_connection(self):
        self._set_custom_connection_id()
        self._set_uuid()
        self._set_interface_name()
        self._set_connection_type()
        self._set_connection_user_owned()
        self.connection.add_setting(self._connection_settings)

        self._set_route()
        self._set_dns()
        self._set_vpn_settings()

        self.connection.verify()

    def _set_custom_connection_id(self):
        self._connection_settings.set_property(NM.SETTING_CONNECTION_ID, self._get_servername())

    def _set_uuid(self):
        self._connection_settings.set_property(NM.SETTING_CONNECTION_UUID, self._unique_id)

    def _set_interface_name(self):
        self._connection_settings.set_property(
            NM.SETTING_CONNECTION_INTERFACE_NAME, self.VIRTUAL_DEVICE_NAME
        )

    def _set_connection_type(self):
        self._connection_settings.set_property(
            NM.SETTING_CONNECTION_TYPE, NM.SETTING_VPN_SETTING_NAME
        )

    def _set_connection_user_owned(self):
        self._connection_settings.add_permission(
            NM.SETTING_USER_SETTING_NAME,
            getuser(),
            None
        )

    def _set_route(self):
        ipv4_config = NM.SettingIP4Config.new()
        ipv6_config = NM.SettingIP6Config.new()

        # We set SETTING_IP4_CONFIG_METHOD_AUTO so that the network manager
        # sets up automatic routing to the VPN server IP, to avoid routing
        # loops.
        #
        # Later we'll want to replace this with fwmark which will allow protun
        # to work with split tunneling.
        ipv4_config.set_property(NM.SETTING_IP_CONFIG_METHOD,
                                 NM.SETTING_IP4_CONFIG_METHOD_AUTO)
        ipv4_config.add_address(
            NM.IPAddress.new(socket.AF_INET, _INTERNAL_IPV4_ADDRESS, _INTERNAL_IPV4_PREFIX)
        )

        # IPv6 is not yet supported by the protun plugin
        ipv6_config.set_property(
            NM.SETTING_IP_CONFIG_METHOD, NM.SETTING_IP6_CONFIG_METHOD_DISABLED
        )

        self.connection.add_setting(ipv4_config)
        self.connection.add_setting(ipv6_config)

    def _set_dns(self):
        ipv4_config = self.connection.get_setting_ip4_config()
        self._configure_dns(nm_setting=ipv4_config, ip_version=IPv4Address)
        self.connection.add_setting(ipv4_config)

    def _configure_dns(
        self,
        nm_setting: Union[NM.SettingIP4Config, NM.SettingIP6Config],
        ip_version: Union[IPv4Address, IPv6Address],
        dns_priority: int = _DNS_PRIORITY,
    ):
        """Sets DNS, respecting custom DNS settings."""
        if ip_version not in [IPv4Address, IPv6Address]:
            raise ValueError(f"Unknown IP version: {ip_version}")

        nm_setting.set_property(NM.SETTING_IP_CONFIG_DNS_PRIORITY, dns_priority)
        nm_setting.set_property(NM.SETTING_IP_CONFIG_IGNORE_AUTO_DNS, True)

        # pylint: disable=duplicate-code
        custom_dns_ips = self._settings.custom_dns\
            .get_enabled_dns_list_based_on_ip_version(ip_version)
        ip_addresses = [dns.exploded for dns in custom_dns_ips]

        # Protun does not auto-configure DNS, so we always set it explicitly.
        if self._settings.custom_dns.enabled and ip_addresses:
            nm_setting.set_property(NM.SETTING_IP_CONFIG_DNS, ip_addresses)
        else:
            nm_setting.add_dns(_INTERNAL_IPV4_DNS)
            nm_setting.add_dns_search(_INTERNAL_IPV4_DNS_SEARCH)

    def _protun_ports(self) -> Dict[str, List[int]]:
        """Returns the protun ports as a dict."""
        raise NotImplementedError(
            "This method should be implemented by ProtunUDP, ProtunTCP, etc. subclasses.")

    def _set_vpn_settings(self):
        vpn_settings = NM.SettingVpn.new()
        vpn_settings.set_property(NM.SETTING_VPN_SERVICE_TYPE, SERVICE_TYPE)

        # Build the peers array expected by the protun plugin (settings.rs)
        peer = {
            "id": self._vpnserver.server_name or self._vpnserver.server_ip,
            "endpoint": f"{self._vpnserver.server_ip}",
            "public-key": self._vpnserver.x25519pk,
            "udp-ports": [],
            "tcp-ports": [],
            "tls-ports": [],
            "priority": 0,
        }
        peer.update(self._protun_ports())

        settings_str = json.dumps({
            "version": 1,
            "peers": [peer],
            "pcap-file": None
        }).replace(",", r"\,")  # Escape commas for NetworkManager

        vpn_settings.add_data_item("settings", settings_str)

        # The WireGuard private key is stored as a VPN secret.
        # NM passes it to the protun auth-dialog which forwards it to the plugin.
        vpn_settings.add_secret(
            PRIVATE_KEY,
            self._vpncredentials.pubkey_credentials.wg_private_key
        )

        # Use the keyring to store the connection private key.
        vpn_settings.add_data_item(PRIVATE_KEY_FLAGS,
                                   STORE_PRIVATE_KEY_IN_KEYRING)

        self.connection.add_setting(vpn_settings)

    # pylint: disable=arguments-renamed
    def _on_state_changed(
            self, vpn_connection: NM.VpnConnection, state: int, reason: int
    ):
        """
        Handle VPN plugin state changes emitted by NetworkManager.

        NM emits vpn-state-changed with state and reason whenever the protun
        plugin connection state changes. This translates NM states into
        backend-agnostic state machine events.
        """
        try:
            state = NM.VpnConnectionState(state)
        except ValueError:
            logger.warning("Unexpected VPN connection state: %s", state)
            state = NM.VpnConnectionState.UNKNOWN

        try:
            reason = NM.VpnConnectionStateReason(reason)
        except ValueError:
            logger.warning("Unexpected VPN connection state reason: %s", reason)
            reason = NM.VpnConnectionStateReason.UNKNOWN

        logger.debug(
            "Protun connection state changed: state=%s, reason=%s",
            state.value_name, reason.value_name
        )

        if state is NM.VpnConnectionState.ACTIVATED:
            logger.info("Starting local agent for domain: %s", self._vpnserver.domain)
            self._async_start_local_agent_listener()
            self._notify_subscribers_threadsafe(
                events.Connected(EventContext(connection=self))
            )
        elif state is NM.VpnConnectionState.FAILED:
            if reason in [
                NM.VpnConnectionStateReason.CONNECT_TIMEOUT,
                NM.VpnConnectionStateReason.SERVICE_START_TIMEOUT,
            ]:
                self._notify_subscribers_threadsafe(
                    events.Timeout(EventContext(connection=self, reason=reason))
                )
            elif reason in [
                NM.VpnConnectionStateReason.NO_SECRETS,
                NM.VpnConnectionStateReason.LOGIN_FAILED,
            ]:
                self._notify_subscribers_threadsafe(
                    events.AuthDenied(EventContext(connection=self, reason=reason))
                )
            else:
                self._notify_subscribers_threadsafe(
                    events.UnexpectedError(EventContext(connection=self, reason=reason))
                )
        elif state is NM.VpnConnectionState.DISCONNECTED:
            if reason is NM.VpnConnectionStateReason.USER_DISCONNECTED:
                self._async_stop_local_agent_listener()
                self._notify_subscribers_threadsafe(
                    events.Disconnected(EventContext(connection=self, reason=reason))
                )
            elif reason is NM.VpnConnectionStateReason.DEVICE_DISCONNECTED:
                self._async_stop_local_agent_listener()
                self._notify_subscribers_threadsafe(
                    events.DeviceDisconnected(EventContext(connection=self, reason=reason))
                )
            else:
                self._notify_subscribers_threadsafe(
                    events.UnexpectedError(EventContext(connection=self, reason=reason))
                )
        else:
            logger.debug("Ignoring VPN state change: %s", state.value_name)

    def _initialize_persisted_connection(
            self, connection_id: str
    ) -> states.State:
        """Initialize from a persisted connection, restarting the local agent if connected."""
        state = super()._initialize_persisted_connection(connection_id)

        if isinstance(state, states.Connected):
            self._async_start_local_agent_listener()
        return state

    async def update_credentials(self, credentials):
        """Notifies the VPN server that the certificate needs a refresh."""
        await super().update_credentials(credentials)
        await self._start_local_agent_listener()

    @property
    def are_feature_updates_applied_when_active(self) -> bool:
        """
        Returns whether connection feature updates are applied on the fly
        while the connection is already active, without restarting it.
        """
        return True

    async def update_settings(self, settings: Settings):
        """Update features on the active agent connection."""
        await super().update_settings(settings)
        if self._agent_listener.is_running:  # noqa: E501 # pylint: disable=line-too-long # nosemgrep: python.lang.maintainability.is-function-without-parentheses.is-function-without-parentheses
            await self._request_connection_features(settings.features)

    @classmethod
    def validate(cls):
        if cls.plugin_exists is None:
            cls.plugin_exists = cls._plugin_exists(cls.PLUGIN_NAME)
        return cls.plugin_exists


class ProtunUDP(Protun):
    """Protun UDP protocol implementation."""

    protocol = "protun-udp"
    ui_protocol = "Wireguard UDP"

    @classmethod
    def get_priority(cls):
        """Returns the priority of the implementation. Lower values indicate higher priority."""
        return 2

    @classmethod
    def get_key(cls):
        """Returns the protocol name."""
        return cls.protocol

    @classmethod
    def get_protocol_group(cls) -> str:
        """Returns the protocol group."""
        return "protun"

    def _protun_ports(self) -> Dict[str, List[int]]:
        """Returns the protun ports as a dict."""
        return {
            "udp-ports": self._vpnserver.wireguard_ports.udp
        }


class ProtunTCP(Protun):
    """Protun TCP protocol implementation."""

    protocol = "protun-tcp"
    ui_protocol = "Wireguard TCP"

    @classmethod
    def get_priority(cls):
        """Returns the priority of the implementation. Lower values indicate higher priority."""
        return 3

    @classmethod
    def get_key(cls):
        """Returns the protocol name."""
        return cls.protocol

    @classmethod
    def get_protocol_group(cls) -> str:
        """Returns the protocol group."""
        return "protun"

    def _protun_ports(self) -> Dict[str, List[int]]:
        """Returns the protun ports as a dict."""
        return {
            "tcp-ports": self._vpnserver.wireguard_ports.tcp
        }


class ProtunTLS(Protun):
    """Protun TLS protocol implementation."""

    protocol = "protun-tls"
    ui_protocol = "Stealth"

    @classmethod
    def get_priority(cls):
        """Returns the priority of the implementation. Lower values indicate higher priority."""
        return 4

    @classmethod
    def get_key(cls):
        """Returns the protocol name."""
        return cls.protocol

    @classmethod
    def get_protocol_group(cls) -> str:
        """Returns the protocol group."""
        return "protun"

    def _protun_ports(self) -> Dict[str, List[int]]:
        """Returns the protun ports as a dict."""
        return {
            "tls-ports": self._vpnserver.wireguard_ports.tls
        }


class ProtunAuto(Protun):
    """
    Protun protocol implementation, automatically selecting the best
    available transport protocol.
    """

    protocol = "protun-auto"
    ui_protocol = "Auto"

    @classmethod
    def get_priority(cls):
        """Returns the priority of the implementation. Lower values indicate higher priority."""
        return 1

    @classmethod
    def get_key(cls):
        """Returns the protocol name."""
        return cls.protocol

    @classmethod
    def get_protocol_group(cls) -> str:
        """Returns the protocol group."""
        return "protun"

    def _protun_ports(self) -> Dict[str, List[int]]:
        """Returns the protun ports as a dict."""
        return {
            "udp-ports": self._vpnserver.wireguard_ports.udp,
            "tcp-ports": self._vpnserver.wireguard_ports.tcp,
            "tls-ports": self._vpnserver.wireguard_ports.tls
        }
