"""
This module contains the backends implementing the supported OpenVPN protocols.


Copyright (c) 2023 Proton AG

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
from typing import Union
from ipaddress import IPv4Address, IPv6Address
import socket
import uuid
import logging
from getpass import getuser
from concurrent.futures import Future
from dataclasses import dataclass

import gi

gi.require_version("NM", "1.0")  # noqa: required before importing NM module
# pylint: disable=wrong-import-position
from gi.repository import NM

from proton.vpn.connection import events, states
from proton.vpn.connection.events import EventContext
from proton.vpn.connection.interfaces import Settings
from proton.vpn.backend.linux.networkmanager.core import (LinuxNetworkManager,
                                                          LocalAgentMixin)


logger = logging.getLogger(__name__)


@dataclass
class Config:
    """Contains all specific details for networking configuration."""
    address: str
    address_prefix: int
    dns_ip: str
    allowed_ip: str
    dns_search: str = "~"
    dns_priority: int = -1500


@dataclass
class WireGuardConfig:
    """Contains networking configurations for both IPv4/6."""
    ipv4: Config
    ipv6: Config

    def get_dns_ip_for_protocol_version(self, ip_version: Union[IPv4Address, IPv6Address]):
        """Returns dns IP value based on IP version."""
        if ip_version == IPv4Address:
            return self.ipv4.dns_ip
        return self.ipv6.dns_ip

    def get_dns_search_for_protocol_version(self, ip_version: Union[IPv4Address, IPv6Address]):
        """Returns dns search value based on IP version."""
        if ip_version == IPv4Address:
            return self.ipv4.dns_search
        return self.ipv6.dns_search


wg_config = WireGuardConfig(
    ipv4=Config(
        address="10.2.0.2",
        address_prefix=32,
        dns_ip="10.2.0.1",
        allowed_ip="0.0.0.0/0",
    ),
    ipv6=Config(
        address="2a07:b944::2:2",
        address_prefix=128,
        dns_ip="2a07:b944::2:1",
        allowed_ip="::/0",
    )
)


class Wireguard(LinuxNetworkManager, LocalAgentMixin):
    """Creates a Wireguard connection."""
    SIGNAL_NAME = "state-changed"
    VIRTUAL_DEVICE_NAME = "proton0"
    protocol = "wireguard"
    ui_protocol = "WireGuard"
    connection = None

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        LocalAgentMixin.__init__(self)
        self._connection_settings = None

    def setup(self) -> Future:
        """Methods that creates and applies any necessary changes to the connection."""
        self._generate_connection()
        self._modify_connection()
        return self.nm_client.add_connection_async(self.connection)

    def _generate_connection(self):
        self._unique_id = str(uuid.uuid4())
        self._connection_settings = NM.SettingConnection.new()
        self.connection = NM.SimpleConnection.new()

    async def update_credentials(self, credentials):
        """Notifies the vpn server that the wireguard certificate needs a refresh."""
        await super().update_credentials(credentials)
        await self._start_local_agent_listener()

    @property
    def are_feature_updates_applied_when_active(self) -> bool:
        """
        Returns whether the connection features updates are applied on the fly
        while the connection is already active, without restarting the connection.
        """
        return True

    async def update_settings(self, settings: Settings):
        """Update features on the active agent connection."""
        await super().update_settings(settings)
        if self._agent_listener.is_running:  # noqa: E501 # pylint: disable=line-too-long # nosemgrep: python.lang.maintainability.is-function-without-parentheses.is-function-without-parentheses
            await self._request_connection_features(settings.features)

    def _modify_connection(self):
        self._set_custom_connection_id()
        self._set_uuid()
        self._set_interface_name()
        self._set_connection_type()
        self._set_connection_user_owned()
        self.connection.add_setting(self._connection_settings)

        self._set_route()
        self._set_dns()
        self._set_wireguard_properties()

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
            NM.SETTING_CONNECTION_TYPE, NM.SETTING_WIREGUARD_SETTING_NAME
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

        ipv4_config.set_property(NM.SETTING_IP_CONFIG_METHOD, NM.SETTING_IP4_CONFIG_METHOD_MANUAL)
        ipv4_config.add_address(
            NM.IPAddress.new(socket.AF_INET, wg_config.ipv4.address, wg_config.ipv4.address_prefix)
        )

        if self.enable_ipv6_support:
            ipv6_config.set_property(
                NM.SETTING_IP_CONFIG_METHOD, NM.SETTING_IP6_CONFIG_METHOD_MANUAL
            )
            ipv6_config.add_address(
                NM.IPAddress.new(
                    socket.AF_INET6, wg_config.ipv6.address, wg_config.ipv6.address_prefix
                )
            )
        else:
            ipv6_config.set_property(
                NM.SETTING_IP_CONFIG_METHOD, NM.SETTING_IP6_CONFIG_METHOD_DISABLED
            )

        self.connection.add_setting(ipv4_config)
        self.connection.add_setting(ipv6_config)

    def _set_dns(self):
        ipv4_config = self.connection.get_setting_ip4_config()
        ipv6_config = self.connection.get_setting_ip6_config()

        self._configure_dns(nm_setting=ipv4_config, ip_version=IPv4Address)
        if self.enable_ipv6_support:
            self._configure_dns(nm_setting=ipv6_config, ip_version=IPv6Address)

        self.connection.add_setting(ipv4_config)
        self.connection.add_setting(ipv6_config)

    def _configure_dns(
        self,
        nm_setting: Union[NM.SettingIP4Config, NM.SettingIP6Config],
        ip_version: Union[IPv4Address, IPv6Address],
        dns_priority: int = -1500,
    ):
        """Sets DNS."""
        if ip_version not in [IPv4Address, IPv6Address]:
            raise ValueError(f"Unknown IP version: {ip_version}")

        nm_setting.set_property(NM.SETTING_IP_CONFIG_DNS_PRIORITY, dns_priority)
        nm_setting.set_property(NM.SETTING_IP_CONFIG_IGNORE_AUTO_DNS, True)

        # pylint: disable=duplicate-code
        custom_dns_ips = self._settings.custom_dns\
            .get_enabled_dns_list_based_on_ip_version(ip_version)
        ip_addresses = [dns.exploded for dns in custom_dns_ips]

        # If custom DNS is disabled or there are no IP addresses then
        # we need to set anyway the DNS because WG does not handle it automatically
        # like OpenVPN does.
        if self._settings.custom_dns.enabled and ip_addresses:
            nm_setting.set_property(NM.SETTING_IP_CONFIG_DNS, ip_addresses)
        else:
            nm_setting.add_dns(wg_config.get_dns_ip_for_protocol_version(ip_version))
            nm_setting.add_dns_search(wg_config.get_dns_search_for_protocol_version(ip_version))

    def _set_wireguard_properties(self):
        peer = NM.WireGuardPeer.new()
        wireguard_config = NM.SettingWireGuard.new()

        peer.append_allowed_ip(wg_config.ipv4.allowed_ip, False)
        peer.set_endpoint(
            f"{self._vpnserver.server_ip}:{self._vpnserver.wireguard_ports.udp[0]}",
            False
        )

        peer.set_public_key(self._vpnserver.x25519pk, False)

        if self.enable_ipv6_support:
            peer.append_allowed_ip(wg_config.ipv6.allowed_ip, False)

        # Seal the NM.WireGuardPeer instance. Afterwards, it is a bug to call all functions that
        # modify the instance (except ref/unref). A sealed instance cannot be unsealed again,
        # but you can create an unsealed copy with NM.WireGuardPeer.new_clone().
        # https://lazka.github.io/pgi-docs/index.html#NM-1.0/classes/WireGuardPeer.html#NM.WireGuardPeer.seal
        peer.seal()

        # Ensures that the configurations are valid
        # https://lazka.github.io/pgi-docs/index.html#NM-1.0/classes/WireGuardPeer.html#NM.WireGuardPeer.is_valid
        peer.is_valid(True, True)
        wireguard_config.append_peer(peer)

        wireguard_config.set_property(
            NM.SETTING_WIREGUARD_PRIVATE_KEY,
            self._vpncredentials.pubkey_credentials.wg_private_key
        )

        self.connection.add_setting(wireguard_config)

    # pylint: disable=arguments-renamed
    def _on_state_changed(
            self, _: NM.ActiveConnection, state: int, reason: int
    ):
        """
            When the connection state changes, NM emits a signal with the state and
            reason for the change. This callback will receive these updates
            and translate for them accordingly for the state machine,
            as the state machine is backend agnostic.

            :param state: connection state update
            :type state: int
            :param reason: the reason for the state update
            :type reason: int
        """
        state = NM.ActiveConnectionState(state)
        reason = NM.ActiveConnectionStateReason(reason)

        logger.debug(
            "Wireguard connection state changed: state=%s, reason=%s",
            state.value_name, reason.value_name
        )

        if state is NM.ActiveConnectionState.ACTIVATED:
            self._async_start_local_agent_listener()
        elif state == NM.ActiveConnectionState.DEACTIVATED:
            self._async_stop_local_agent_listener()
            self._notify_subscribers_threadsafe(
                events.Disconnected(EventContext(connection=self))
            )
        else:
            logger.debug("Ignoring VPN state change: %s", state.value_name)

    def _initialize_persisted_connection(
            self, connection_id: str
    ) -> states.State:
        """Implemented in wireguard so we can start local agent listener."""
        state = super()._initialize_persisted_connection(connection_id)

        if isinstance(state, states.Connected):
            self._async_start_local_agent_listener()
        return state

    @classmethod
    def _get_priority(cls):
        return 1

    @classmethod
    def _validate(cls):
        # FIX ME: This should do a validation to ensure that NM can be used
        return True
