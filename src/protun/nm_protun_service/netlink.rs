// -----------------------------------------------------------------------------
// Copyright (c) 2025 Proton AG
//
// This file is part of ProtonVPN.
//
// ProtonVPN is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// ProtonVPN is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with ProtonVPN.  If not, see <https://www.gnu.org/licenses/>.
// -----------------------------------------------------------------------------
//! Netlink operations for VPN interface management.
//!
//! This module provides async functions for interface configuration (up, MTU).

use futures::stream::TryStreamExt;
use rtnetlink::new_connection;

use super::error::{Error, Result};

const ROUTE_ALREADY_EXISTS: i32 = -libc::EEXIST; // Entry Exists
const ROUTE_NO_LONGER_EXISTS: i32 = -libc::ESRCH; // Error Search

const LINUX_MAIN_PRIORITY : u32 = 32766; // https://man7.org/linux/man-pages/man8/ip-rule.8.html
const PROTUN_FWMARK_PRIORITY : u32 = LINUX_MAIN_PRIORITY-1;
const PROTUN_SUPPRESS_PRIORITY : u32 = LINUX_MAIN_PRIORITY-2;

#[derive(Debug)]
struct RoutingMessages {
    default_route:          netlink_packet_route::route::RouteMessage,
    fatal_killswitch_route: netlink_packet_route::route::RouteMessage,
    suppress_rule:          netlink_packet_route::rule::RuleMessage,
    fwmark_rule:            netlink_packet_route::rule::RuleMessage,
}

/// A wrapper around rtnetlink Handle for interface operations.
pub struct NetlinkHandle {
    handle: rtnetlink::Handle, // TODO: LT Record the dependency we're using
    // so it can be checked.
    // Keep the connection task alive
    _connection_task: tokio::task::JoinHandle<()>,
}

impl NetlinkHandle {
    /// Create a new netlink handle.
    pub fn new() -> Result<Self> {
        let (connection, handle, _) = new_connection()?;

        Ok(Self {
            handle,
            _connection_task: tokio::spawn(connection),
        })
    }

    /// Get interface index by name.
    async fn get_interface_index(&self, name: &str) -> Result<u32> {
        let mut links = self
            .handle
            .link()
            .get()
            .match_name(name.to_string())
            .execute();

        if let Some(link) = links.try_next().await? {
            Ok(link.header.index)
        } else {
            Err(Error::IO(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("Interface {} not found", name),
            )))
        }
    }

    /// Configure interface: set UP and MTU.
    pub async fn configure_interface(
        &self,
        name: &str,
        mtu: u32,
    ) -> Result<()> {
        let if_index = self.get_interface_index(name).await?;
        let link_message = rtnetlink::LinkMessageBuilder::<rtnetlink::LinkUnspec>::new()
            .index(if_index)
            .mtu(mtu)
            .up()
            .build();

        self.handle
            .link()
            .set(link_message)
            .execute()
            .await?;

        log::info!("Interface {} configured: UP, MTU={}", name, mtu);
        Ok(())
    }

    /// Create IPv4 route and rules:
    ///     default dev $if_index proto static scope link metric 50    (table $fwmark)
    ///     unreachable default metric 100                             (table $fwmark)
    ///     from all lookup main suppress_prefixlength 0 proto static  (priority 32764)
    ///     not from all fwmark $fwmark lookup $fwmark proto static    (priority 32765)
    fn ipv4_routing_messages(if_index: u32, fwmark: u32) -> Result<RoutingMessages> {
        Self::routing_messages(
            std::net::IpAddr::V4(
                std::net::Ipv4Addr::new(0, 0, 0, 0)),
            netlink_packet_route::AddressFamily::Inet,
            if_index, fwmark
        )
    }

    /// Create IPv6 route and rules:
    ///     ::/0 dev $if_index proto static metric 50                  (table $fwmark)
    ///     unreachable ::/0 metric 100                                (table $fwmark)
    ///     from all lookup main suppress_prefixlength 0 proto static  (priority 32764)
    ///     not from all fwmark $fwmark lookup $fwmark proto static    (priority 32765)
    fn ipv6_routing_messages(if_index: u32, fwmark: u32) -> Result<RoutingMessages> {
        Self::routing_messages(
            std::net::IpAddr::V6(
                std::net::Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)),
            netlink_packet_route::AddressFamily::Inet6,
            if_index, fwmark
        )
    }

    /// Builds the four netlink messages for fwmark-based routing:
    ///
    ///   route:            default via tun (metric 50, table $fwmark)
    ///                     — send all traffic through the tunnel
    ///   fatal_killswitch: unreachable default (metric 100, table $fwmark)
    ///                     — drop traffic if the tunnel disappears
    ///   suppress:         lookup main, suppress /0 (priority 32764)
    ///                     — allow LAN routes, block the default route
    ///   fwmark_rule:      NOT fwmark → lookup $fwmark (priority 32765)
    ///                     — unmarked packets enter VPN table; marked
    ///                       packets (WireGuard socket) bypass it
    fn routing_messages(default_prefix: std::net::IpAddr,
                        family: netlink_packet_route::AddressFamily,
                        if_index: u32, fwmark: u32) -> Result<RoutingMessages>
    {
        use netlink_packet_route::route::{RouteAttribute, RouteProtocol, RouteType};
        use netlink_packet_route::rule::{RuleAction, RuleAttribute, RuleFlags, RuleMessage};
        use netlink_packet_route::AddressFamily;

        // Make sure all default traffic goes through this route
        let mut default_route = rtnetlink::RouteMessageBuilder::<std::net::IpAddr>::new()
            .destination_prefix(default_prefix.clone(), 0)
                .map_err(|e| Error::NetLink(format!("{e}")))?
            .output_interface(if_index)
            .table_id(fwmark)
            .build();
        default_route.attributes.push(RouteAttribute::Priority(50));

        // If the protun process crashes, this catches traffic
        let mut fatal_killswitch_route = rtnetlink::RouteMessageBuilder::<std::net::IpAddr>::new()
            .destination_prefix(default_prefix, 0)
                .map_err(|e| Error::NetLink(format!("{e}")))?
            .table_id(fwmark)
            .build();
        fatal_killswitch_route.header.kind = RouteType::Unreachable;
        fatal_killswitch_route.attributes.push(RouteAttribute::Priority(100));
        
        // Only allow explicit routes that are in the main table, default
        // routes are ignored.
        //
        // This is done by suppressing routes that have a prefix of 0 (default).
        let mut suppress_rule = RuleMessage::default();
        suppress_rule.header.family = family;
        suppress_rule.header.action = RuleAction::ToTable;
        suppress_rule.attributes.push(RuleAttribute::Table(libc::RT_TABLE_MAIN as u32));
        suppress_rule.attributes.push(RuleAttribute::SuppressPrefixLen(0));
        suppress_rule.attributes.push(RuleAttribute::Priority(PROTUN_SUPPRESS_PRIORITY));
        suppress_rule.attributes.push(RuleAttribute::Protocol(RouteProtocol::Static));

        // Dispatch unmarked packets to our our routing table
        let mut fwmark_rule = RuleMessage::default();
        fwmark_rule.header.family = family;
        fwmark_rule.header.action = RuleAction::ToTable;
        fwmark_rule.attributes.push(RuleAttribute::FwMark(fwmark));
        fwmark_rule.attributes.push(RuleAttribute::Table(fwmark));
        fwmark_rule.attributes.push(RuleAttribute::Priority(PROTUN_FWMARK_PRIORITY));
        fwmark_rule.attributes.push(RuleAttribute::Protocol(RouteProtocol::Static));
        fwmark_rule.header.flags.insert(RuleFlags::Invert);

        Ok(RoutingMessages {
            default_route,
            fatal_killswitch_route,
            suppress_rule,
            fwmark_rule })
    }

    async fn add_route(
        &self,
        route: netlink_packet_route::route::RouteMessage,
    ) -> Result<()> {
        match self.handle.route().add(route.clone()).execute().await {
            Err(rtnetlink::Error::NetlinkError(e))
                if e.code.map(|c| c.get()) == Some(ROUTE_ALREADY_EXISTS) => {
                    log::warn!(
                        "Skipping {route:?}, attempted to add route that already exists"
                    );
                    Ok(())
                },
            result => result
        }.map_err(Error::from)
    }

    async fn add_rule(
        &self,
        rule: netlink_packet_route::rule::RuleMessage,
    ) -> Result<()> {
        let mut req = self.handle.rule().add();
        *req.message_mut() = rule.clone();
        match req.execute().await {
            Err(rtnetlink::Error::NetlinkError(e))
                if e.code.map(|c| c.get()) == Some(ROUTE_ALREADY_EXISTS) => {
                    log::warn!(
                        "Skipping {rule:?}, attempted to add rule that already exists"
                    );
                    Ok(())
                },
            result => result
        }.map_err(Error::from)
    }

    async fn add_routing(&self, msgs: RoutingMessages) -> Result<()> {
        log::info!("Adding {msgs:?}");
        self.add_route(msgs.default_route).await?;
        self.add_route(msgs.fatal_killswitch_route).await?;
        self.add_rule(msgs.suppress_rule).await?;
        self.add_rule(msgs.fwmark_rule).await?;
        Ok(())
    }

    async fn del_route(&self, label: &str, route: netlink_packet_route::route::RouteMessage) {
        match self.handle.route().del(route).execute().await {
            // Dont worry if the route we're trying to remove no longer
            // exists
            Err(rtnetlink::Error::NetlinkError(e))
                if e.code.map(|c| c.get()) == Some(ROUTE_NO_LONGER_EXISTS) => {},
            // If there's an error deleting the route, then just log it
            // and move on, we have to continue with the cleanup
            // and get rid of as much as we can
            Err(e) => log::error!("Failed to delete route {label}: {e}"),
            Ok(_) => {},
        }
    }

    async fn del_rule(&self, label: &str, rule: netlink_packet_route::rule::RuleMessage) {
        if let Err(e) = self.handle.rule().del(rule).execute().await {
            log::error!("Failed to delete rule {label}: {e}");
        }
    }

    async fn del_routing(&self, msgs: RoutingMessages) {
        log::info!("Deleting {msgs:?}");
        self.del_rule("fwmark_rule", msgs.fwmark_rule).await;
        self.del_rule("suppress_rule", msgs.suppress_rule).await;
        self.del_route("fatal_killswitch_route", msgs.fatal_killswitch_route).await;

        // The default route can be cleaned up by network manager
        // before we get around to removing it.
        //
        // Give it a go, but don't worry if it no longer exists.
        self.del_route("default_route", msgs.default_route).await;
    }

    pub async fn setup_routing(
        &self,
        fwmark: u32,
        tun_interface: &str,
        ipv6: bool,
    ) -> Result<()> {
        let if_index = self.get_interface_index(tun_interface).await?;

        if ipv6 {
            self.add_routing(Self::ipv6_routing_messages(if_index, fwmark)?).await?;
        }

        self.add_routing(Self::ipv4_routing_messages(if_index, fwmark)?).await?;

        Ok(())
    }

    pub async fn teardown_routing(
        &self,
        fwmark: u32,
        tun_interface: &str,
        ipv6: bool,
    ) -> Result<()> {
        let if_index = self.get_interface_index(tun_interface).await?;

        log::info!("Tearing down routing for {}", tun_interface);

        self.del_routing(Self::ipv4_routing_messages(if_index, fwmark)?).await;

        if ipv6 {
            self.del_routing(Self::ipv6_routing_messages(if_index, fwmark)?).await;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use netlink_packet_route::{
        route::{RouteAttribute, RouteProtocol, RouteType},
        rule::{RuleAction, RuleAttribute, RuleFlags},
        AddressFamily,
    };

    const TEST_FWMARK: u32 = 0xEAD1_5EED;
    const TEST_IF_INDEX: u32 = 7;

    fn assert_routing_messages(msgs: &RoutingMessages, family: AddressFamily) {
        assert!(msgs.default_route.attributes.contains(&RouteAttribute::Priority(50)));
        assert_eq!(msgs.default_route.header.kind, RouteType::Unicast);

        assert!(msgs.fatal_killswitch_route.attributes.contains(&RouteAttribute::Priority(100)));
        assert_eq!(msgs.fatal_killswitch_route.header.kind, RouteType::Unreachable);

        let suppress = &msgs.suppress_rule;
        assert_eq!(suppress.header.family, family);
        assert_eq!(suppress.header.action, RuleAction::ToTable);
        assert!(suppress.attributes.contains(&RuleAttribute::Table(libc::RT_TABLE_MAIN as u32)));
        assert!(suppress.attributes.contains(&RuleAttribute::SuppressPrefixLen(0)));
        assert!(suppress.attributes.contains(&RuleAttribute::Priority(32764)));
        assert!(suppress.attributes.contains(&RuleAttribute::Protocol(RouteProtocol::Static)));

        let fwmark = &msgs.fwmark_rule;
        assert_eq!(fwmark.header.family, family);
        assert_eq!(fwmark.header.action, RuleAction::ToTable);
        assert!(fwmark.attributes.contains(&RuleAttribute::FwMark(TEST_FWMARK)));
        assert!(fwmark.attributes.contains(&RuleAttribute::Table(TEST_FWMARK)));
        assert!(fwmark.attributes.contains(&RuleAttribute::Priority(32765)));
        assert!(fwmark.attributes.contains(&RuleAttribute::Protocol(RouteProtocol::Static)));
        assert!(fwmark.header.flags.contains(RuleFlags::Invert));
    }

    #[test]
    fn test_ipv4_routing_messages() {
        let msgs = NetlinkHandle::ipv4_routing_messages(TEST_IF_INDEX, TEST_FWMARK).unwrap();
        assert_routing_messages(&msgs, AddressFamily::Inet);
    }

    #[test]
    fn test_ipv6_routing_messages() {
        let msgs = NetlinkHandle::ipv6_routing_messages(TEST_IF_INDEX, TEST_FWMARK).unwrap();
        assert_routing_messages(&msgs, AddressFamily::Inet6);
    }
}
