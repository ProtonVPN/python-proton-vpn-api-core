// -----------------------------------------------------------------------------
// Copyright (c) 2026 Proton AG
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
//! The nftables tables behind the kill switch.
//!
//! [`Tables`] is the seam between [`FirewallKillSwitch`]'s orchestration and
//! the netfilter calls, which need `CAP_NET_ADMIN`. It sits at table level
//! rather than at the netlink level, so a test double deals in "which tables
//! are installed" instead of opaque nftnl batches.
//!
//! [`FirewallKillSwitch`]: super::FirewallKillSwitch

use std::ffi::{CStr, CString};

use async_trait::async_trait;
use nftnl::{Batch, Chain, Hook, MsgType, Policy, ProtoFamily, Table};

use super::super::config::FirewallConfig;
use super::super::error::{ConfigError, Result};
use super::expr::End;
use super::netlink::{self, send_and_process};
use super::rules;

const TABLE_NAME: &CStr = c"proton_vpn_ks";
// Separate table so IPv6 leak protection can be enabled and removed without
// touching the full kill switch, and vice versa.
const IPV6_TABLE_NAME: &CStr = c"proton_vpn_ks_ipv6";

// Family names as nft spells them, for reporting.
const TABLE_FAMILY: &str = "inet";
const IPV6_TABLE_FAMILY: &str = "ip6";
const IN_CHAIN_NAME: &CStr = c"input";
const OUT_CHAIN_NAME: &CStr = c"output";
const FWD_CHAIN_NAME: &CStr = c"forward";
const LOOPBACK_IFACE: &CStr = c"lo";

// nftables filter priority — 0 runs before positive values, after negative
// ones. This is the standard priority for filtering rules (NF_IP_PRI_FILTER).
const FILTER_PRIORITY: i32 = 0;

/// Installing and removing the two kill switch tables. A trait so the kill
/// switch can be tested without `CAP_NET_ADMIN`; production uses
/// [`NftTables`].
#[async_trait]
pub(crate) trait Tables: Send + Sync {
    /// Install `inet proton_vpn_ks`, replacing any rules already in it.
    async fn apply_kill_switch(&self, config: &FirewallConfig) -> Result<()>;

    /// Remove `inet proton_vpn_ks`. Idempotent.
    async fn remove_kill_switch(&self) -> Result<()>;

    /// Install `ip6 proton_vpn_ks_ipv6`, replacing any rules already in it.
    async fn apply_ipv6_leak_protection(
        &self,
        config: &FirewallConfig,
    ) -> Result<()>;

    /// Remove `ip6 proton_vpn_ks_ipv6`. Idempotent.
    async fn remove_ipv6_leak_protection(&self) -> Result<()>;

    /// The kill switch tables currently installed, in a stable order, each as
    /// `"<family> <name>"` — the form `nft list table` expects.
    async fn installed(&self) -> Result<Vec<String>>;
}

/// [`Tables`] backed by netfilter, over netlink.
#[derive(Default)]
pub(crate) struct NftTables;

#[async_trait]
impl Tables for NftTables {
    async fn apply_kill_switch(&self, config: &FirewallConfig) -> Result<()> {
        let tunnel_iface = iface_name(&config.tunnel_iface)?;

        let table = Table::new(TABLE_NAME, ProtoFamily::Inet);
        let mut batch = Batch::new();

        // Wipe any existing rules, then recreate. Both happen in the same
        // batch, so the table is never left absent.
        remove_table(&mut batch, &table);
        batch.add(&table, MsgType::Add);

        // Output chain: drop by default — only explicitly allowed traffic passes
        // through.
        let out_chain = add_chain(&mut batch, &table, OUT_CHAIN_NAME, Hook::Out);
        // Input chain: drop by default — blocks unsolicited incoming connections.
        let in_chain = add_chain(&mut batch, &table, IN_CHAIN_NAME, Hook::In);
        // Forward chain: drop by default — blocks VMs and containers from
        // bypassing the VPN.
        let fwd_chain =
            add_chain(&mut batch, &table, FWD_CHAIN_NAME, Hook::Forward);

        // Allow loopback traffic in both directions.
        rules::add_loopback_rules(
            &mut batch,
            &out_chain,
            &in_chain,
            LOOPBACK_IFACE,
        );

        // Allow inbound established/related connections. No interface restriction
        // on the input chain: the encrypted WireGuard return traffic from the
        // server arrives on the physical interface (not on the tunnel), so it
        // can't be matched by tunnel interface here. This is safe because
        // conntrack only marks a connection established if we already permitted it
        // outbound. On the forward chain we keep the tunnel-interface restriction,
        // since forwarded return traffic for VMs arrives decrypted on the tunnel.
        //
        // TODO: allow VPN port forwarding. ProtonVPN's NAT-PMP hands us a port on
        // the VPN gateway; remote peers then open *new* inbound connections to us
        // through the tunnel. Right now we only accept established/related
        // inbound, so those fresh connections hit the default drop. To support it,
        // add an input-chain rule accepting new inbound on the tunnel interface
        // (iif == tunnel) to the forwarded port, for TCP and UDP. The forwarded
        // port is assigned at runtime by NAT-PMP and can change, so it must be
        // passed in (new `FirewallConfig` field) and the rule rebuilt when
        // it's
        // renewed — scope the rule to that specific port rather than opening all
        // inbound on the tunnel.
        rules::add_allow_established_connections_rule(&mut batch, &in_chain, None);
        rules::add_allow_established_connections_rule(
            &mut batch,
            &fwd_chain,
            Some(&tunnel_iface),
        );

        // Allow NDP so IPv6 neighbor/router discovery works on the local network.
        rules::add_ndp_rules(&mut batch, &out_chain, &in_chain);

        // Allow DHCP so the machine can renew its IP lease while the KS is active.
        rules::add_dhcp_client_rules(&mut batch, &out_chain, &in_chain);

        // Allow DHCP server broadcasts so NAT'd VMs/containers (e.g. libvirt's
        // default network) can get a lease from this host. Their unicast DHCP
        // traffic is already covered by the LAN rules below.
        rules::add_dhcp_server_rules(&mut batch, &out_chain, &in_chain);

        // Note: NDP and DHCP rules go on the input/output chains (traffic to/from
        // this host) but NOT the forward chain (traffic this host routes between
        // two other machines, e.g. a VM reaching the internet through us). That's
        // fine here: with a NAT'd VM/container, this host is itself the thing
        // handing out IP addresses (DHCP) and answering IPv6 "who is at this
        // address?" (NDP) on the virtual network, so that traffic is to/from this
        // host and the input/output rules — including the DHCP server rules
        // above — cover it.
        // TODO: the one case not covered is if this host ever *passes along* DHCP
        // requests for another network it routes (acting as a "DHCP relay"). Those
        // forwarded DHCPv4 requests are sent to the broadcast address
        // 255.255.255.255, which isn't in LAN_NETS, so they'd hit the default
        // drop. If we ever support that setup, add a forwarded-DHCPv4 rule on the
        // forward chain.

        // TODO: prevent DNS leaks. Drop-by-default stops arbitrary traffic, but
        // the LAN rules below allow plaintext DNS (port 53) to a LAN resolver,
        // bypassing the tunnel. Fix: reject all outgoing port-53 TCP/UDP and then
        // re-allow only tunnel DNS (plus any explicitly configured local
        // resolvers). The DNS drop must be added BEFORE these LAN/tunnel allow
        // rules so queries can't leak to the LAN or to the wrong in-tunnel IP.

        // Allow traffic to/from LAN subnets (local network access). The two
        // families are passed separately so each can be narrowed on its own.
        for nets in [rules::LAN_NETS_V4, rules::LAN_NETS_V6] {
            rules::add_lan_rules(&mut batch, &out_chain, End::Dst, nets);
            rules::add_lan_rules(&mut batch, &in_chain, End::Src, nets);
            rules::add_lan_rules(&mut batch, &fwd_chain, End::Dst, nets);
        }

        // TODO: mitigate CVE-2019-14899. Allowing LAN access lets an attacker on
        // the same LAN infer the in-tunnel IP by sending crafted packets to it
        // when reverse-path filtering is loose. Fix: on the input chain, drop
        // inbound packets whose destination is the tunnel's own IP — added AFTER
        // the tunnel-allow rule so the tunnel itself can still reach that IP.
        // Requires passing the tunnel IP(s) in as an argument; we currently only
        // take the tunnel interface name.

        // Allow traffic on the VPN tunnel interface.
        // Inner packets routed to the wireguard interface carry no fwmark —
        // WireGuard sets the fwmark only on the outer UDP packets it sends to the
        // peer. Without this rule, inner packets are dropped before reaching
        // WireGuard for encapsulation.
        rules::add_tunnel_iface_rule(&mut batch, &out_chain, &tunnel_iface);
        rules::add_tunnel_iface_rule(&mut batch, &fwd_chain, &tunnel_iface);

        // Allow traffic to the VPN server IP — needed during the connecting phase
        // before the tunnel is up and WireGuard starts marking packets with the
        // fwmark.
        if let Some(ip) = config.server_ip {
            // TODO: security gap here: currently we probe the server before
            // bringing the VPN tunnel up. If it wasn't for that, this shouldn't be
            // needed.
            rules::add_server_ip_rule(&mut batch, &out_chain, ip);
        }

        // Allow VPN tunnel traffic — WireGuard marks its own outgoing packets with
        // the fwmark. Everything else is dropped by the default policy above.
        rules::add_fwmark_rule(&mut batch, &out_chain, config.fwmark);
        // TODO: I don't think we need this, since we already have the rule to
        // allow established connections
        rules::add_fwmark_rule(&mut batch, &fwd_chain, config.fwmark);

        // Fail fast on blocked traffic, so apps (and forwarded VMs) get an error
        // rather than hanging until they time out. Added last, since these match
        // unconditionally. The input chain is left to drop silently, so we don't
        // advertise the host to unsolicited inbound. The Drop policies remain the
        // fail-closed backstop: chain policy can only be Accept or Drop, so
        // reject has to be a rule.
        rules::add_reject_rules(&mut batch, &out_chain);
        rules::add_reject_rules(&mut batch, &fwd_chain);

        // TODO: after applying, verify the table was actually installed by
        // querying it back via netlink. A successful send doesn't guarantee the
        // host supports nftables properly; without this check a silent failure
        // would leave the machine unprotected.
        send_and_process(batch.finalize()).await?;

        // TODO: harden kernel sysctls, which the firewall rules can't cover:
        //   - net.ipv4.conf.all.src_valid_mark = 1: make reverse-path filtering
        //     account for the fwmark, so WireGuard's own marked outer packets
        //     aren't dropped by rp_filter (needed to bring the tunnel up on
        //     systems with strict rp_filter). This also covers the *inbound*
        //     server traffic: with strict rp_filter, the encrypted reply from the
        //     VPN server arrives unmarked on the physical interface, and the
        //     reverse-path lookup for an unmarked packet resolves to the tunnel
        //     table — so rpf thinks the reply "should" come from the tunnel and
        //     drops it before our firewall rules even run. We currently rely on
        //     conntrack (established/related on the input chain) to admit that
        //     return traffic, which works only because typical hosts run loose
        //     rp_filter (0 or 2). On a host with strict rp_filter (1) we'd need
        //     this sysctl — or a prerouting rule that stamps the fwmark on inbound
        //     packets from the server IP. The sysctl is the lighter fix since we
        //     have no prerouting chain.
        //   - net.ipv4.conf.all.arp_ignore = 2: only answer ARP requests for an IP
        //     on the interface the request arrived on, from a same-subnet sender.
        //     Stops a LAN attacker from learning the in-tunnel IP by ARP-probing a
        //     physical interface.
        // Decide whether `disable` should restore the originals or leave the
        // hardened values in place.

        log::info!(
            "Kill switch rules applied (fwmark={:#x}, tunnel-iface={}, server-ip={})",
            config.fwmark,
            config.tunnel_iface,
            config
                .server_ip
                .map_or_else(|| "none".to_owned(), |ip| ip.to_string()),
        );

        Ok(())
    }

    async fn remove_kill_switch(&self) -> Result<()> {
        let table = Table::new(TABLE_NAME, ProtoFamily::Inet);
        let mut batch = Batch::new();

        remove_table(&mut batch, &table);
        send_and_process(batch.finalize()).await?;

        log::info!("Kill switch rules removed");

        Ok(())
    }

    async fn apply_ipv6_leak_protection(
        &self,
        config: &FirewallConfig,
    ) -> Result<()> {
        let tunnel_iface = iface_name(&config.tunnel_iface)?;

        let table = Table::new(IPV6_TABLE_NAME, ProtoFamily::Ipv6);
        let mut batch = Batch::new();

        remove_table(&mut batch, &table);
        batch.add(&table, MsgType::Add);

        let out_chain =
            add_chain(&mut batch, &table, OUT_CHAIN_NAME, Hook::Out);
        let in_chain = add_chain(&mut batch, &table, IN_CHAIN_NAME, Hook::In);
        let fwd_chain =
            add_chain(&mut batch, &table, FWD_CHAIN_NAME, Hook::Forward);

        // Order is deliberate: the precise rules come before the broad LAN
        // accepts, so narrowing the latter later stays a local change and cannot
        // silently take neighbour discovery or lease renewal with it.
        rules::add_loopback_rules(
            &mut batch,
            &out_chain,
            &in_chain,
            LOOPBACK_IFACE,
        );

        rules::add_allow_established_connections_rule(
            &mut batch, &in_chain, None,
        );
        rules::add_allow_established_connections_rule(
            &mut batch,
            &fwd_chain,
            Some(&tunnel_iface),
        );

        // Neighbour discovery and DHCPv6: without these, blocking IPv6 breaks
        // address resolution and lease renewal on the local network.
        rules::add_ndp_rules(&mut batch, &out_chain, &in_chain);
        rules::add_dhcpv6_rules(&mut batch, &out_chain, &in_chain);

        let nets = rules::LAN_NETS_V6;
        rules::add_lan_rules(&mut batch, &out_chain, End::Dst, nets);
        rules::add_lan_rules(&mut batch, &in_chain, End::Src, nets);
        rules::add_lan_rules(&mut batch, &fwd_chain, End::Dst, nets);

        // IPv6 reaches the VPN inside the IPv4 tunnel, so tunneled IPv6 has to
        // keep working.
        rules::add_tunnel_iface_rule(&mut batch, &out_chain, &tunnel_iface);
        rules::add_tunnel_iface_rule(&mut batch, &fwd_chain, &tunnel_iface);

        // Split tunneling marks the traffic it excludes from the VPN, so that
        // WireGuard leaves it alone and it goes out the physical interface. That
        // traffic can be IPv6, and blocking it here would break the feature.
        rules::add_fwmark_rule(&mut batch, &out_chain, config.fwmark);
        rules::add_fwmark_rule(&mut batch, &fwd_chain, config.fwmark);

        rules::add_reject_rules(&mut batch, &out_chain);
        rules::add_reject_rules(&mut batch, &fwd_chain);

        log::info!(
            "Enabling IPv6 leak protection (tunnel-iface={})",
            config.tunnel_iface
        );

        send_and_process(batch.finalize()).await?;

        Ok(())
    }

    async fn remove_ipv6_leak_protection(&self) -> Result<()> {
        let table = Table::new(IPV6_TABLE_NAME, ProtoFamily::Ipv6);
        let mut batch = Batch::new();

        remove_table(&mut batch, &table);
        send_and_process(batch.finalize()).await?;

        log::info!("IPv6 leak protection disabled");

        Ok(())
    }

    /// Presence only — the names are all a table dump gives us. Reading the
    /// rules back would mean parsing every expression out of netlink, and
    /// `nft list table` already does that far better.
    ///
    /// Changes nothing, but it still requires `CAP_NET_ADMIN`: netfilter
    /// demands it even to read.
    async fn installed(&self) -> Result<Vec<String>> {
        let installed = netlink::list_tables().await?;

        // A table dump reports names without families, so the family is paired
        // back on here. Our two names are distinctive enough that a same-named
        // table in another family is not a real concern.
        Ok([
            (TABLE_FAMILY, TABLE_NAME),
            (IPV6_TABLE_FAMILY, IPV6_TABLE_NAME),
        ]
        .into_iter()
        .filter(|(_, name)| installed.contains(*name))
        .map(|(family, name)| format!("{family} {}", name.to_string_lossy()))
        .collect())
    }
}

/// Queue an idempotent removal of the table.
///
/// The Add before the Del is what makes it idempotent: deleting a table that is
/// not there would error.
fn remove_table(batch: &mut Batch, table: &Table) {
    batch.add(table, MsgType::Add);
    batch.add(table, MsgType::Del);
}

/// Add a chain that drops everything the subsequent rules don't accept.
fn add_chain<'a>(
    batch: &mut Batch,
    table: &'a Table,
    name: &CStr,
    hook: Hook,
) -> Chain<'a> {
    let mut chain = Chain::new(name, table);
    chain.set_hook(hook, FILTER_PRIORITY);
    chain.set_policy(Policy::Drop);
    batch.add(&chain, MsgType::Add);
    chain
}

/// Convert an interface name into the NUL-terminated form netlink expects.
fn iface_name(iface: &str) -> Result<CString> {
    Ok(CString::new(iface)
        .map_err(|_| ConfigError::InterfaceName(iface.to_owned()))?)
}

#[cfg(test)]
mod tests {
    use super::super::super::error::Error;
    use super::*;

    #[test]
    fn iface_name_accepts_a_plain_name() {
        assert_eq!(iface_name("proton0").unwrap().as_c_str(), c"proton0");
    }

    #[test]
    fn iface_name_rejects_interior_nul() {
        // A NUL byte would silently truncate the name passed to netlink, so a
        // rule could end up matching a different interface than intended.
        let err = iface_name("proton0\0eth0").unwrap_err();

        assert!(matches!(err, Error::Config(ConfigError::InterfaceName(_))));
    }
}
