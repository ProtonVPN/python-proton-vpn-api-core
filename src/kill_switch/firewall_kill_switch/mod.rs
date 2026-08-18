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
//! nftables kill switch for WireGuard-based connections.
//!
//! [`enable`] creates an `inet` table `protonvpn_ks` with three
//! drop-by-default chains — `input`, `output` and `forward` — so inbound,
//! outbound and forwarded (e.g. from VMs/containers) traffic is all blocked
//! unless a rule allows it. Allowed traffic is:
//!
//! - loopback, in both directions
//! - established/related return traffic
//! - the WireGuard tunnel interface, and packets tagged with the fwmark
//! - LAN, link-local and multicast subnets
//! - NDP (IPv6 neighbor/router discovery) and DHCPv4
//! - the VPN server IP during the connecting phase, when
//!   [`Config::server_ip`] is set
//!
//! Everything else is dropped. [`disable`] removes the table entirely.
//!
//! Both calls require `CAP_NET_ADMIN` (netlink/netfilter access).
//!
//! # Known limitations
//!
//! - **LAN blocking not supported.** Local-network traffic is always allowed;
//!   there is no mode that also blocks the LAN yet.
//! - **Port forwarding not supported.** Inbound connections initiated from the
//!   VPN side (e.g. ProtonVPN NAT-PMP) are dropped for now; only return
//!   traffic for connections this host started is allowed in.
//! - **IPv6-only networks not supported.** Address configuration via DHCPv6 is
//!   blocked (only DHCPv4 is allowed), so a host that relies on it can't
//!   obtain or renew its lease while the kill switch is active.

mod expr;
mod netlink;
mod rules;

use std::ffi::{CStr, CString};

use nftnl::{Batch, Chain, Hook, MsgType, Policy, ProtoFamily, Table};

use super::config::Config;
use super::error::{Error, Result};
use expr::End;
use netlink::send_and_process;

const TABLE_NAME: &CStr = c"protonvpn_ks";
const IN_CHAIN_NAME: &CStr = c"input";
const OUT_CHAIN_NAME: &CStr = c"output";
const FWD_CHAIN_NAME: &CStr = c"forward";
const LOOPBACK_IFACE: &CStr = c"lo";

// nftables filter priority — 0 runs before positive values, after negative
// ones. This is the standard priority for filtering rules (NF_IP_PRI_FILTER).
const FILTER_PRIORITY: i32 = 0;

#[derive(Default)]
pub struct FirewallKillSwitch;

impl FirewallKillSwitch
{
    /// Enable the kill switch, replacing any rules a previous call installed.
    ///
    /// Idempotent: calling it twice leaves the same rule set in place.
    pub async fn enable(&mut self, config: &Config) -> Result<()> {
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
        // passed in (new `Config` field) and the rule rebuilt whenever it's
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
        rules::add_dhcp_rules(&mut batch, &out_chain, &in_chain);

        // Note: NDP and DHCP rules go on the input/output chains (traffic to/from
        // this host) but NOT the forward chain (traffic this host routes between
        // two other machines, e.g. a VM reaching the internet through us). That's
        // fine here: with a NAT'd VM/container, this host is itself the thing
        // handing out IP addresses (DHCP) and answering IPv6 "who is at this
        // address?" (NDP) on the virtual network, so that traffic is to/from this
        // host and the input/output rules cover it.
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

        // Allow traffic to/from LAN subnets (local network access).
        rules::add_lan_rules(&mut batch, &out_chain, End::Dst);
        rules::add_lan_rules(&mut batch, &in_chain, End::Src);
        rules::add_lan_rules(&mut batch, &fwd_chain, End::Dst);

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
            "Kill switch enabled (fwmark={:#x}, tunnel-iface={}, server-ip={})",
            config.fwmark,
            config.tunnel_iface,
            config
                .server_ip
                .map_or_else(|| "none".to_owned(), |ip| ip.to_string()),
        );

        Ok(())
    }

    /// Disable the kill switch by removing the nftables table.
    ///
    /// Idempotent: succeeds even when the kill switch was never enabled.
    pub async fn disable(&mut self) -> Result<()> {
        let table = Table::new(TABLE_NAME, ProtoFamily::Inet);
        let mut batch = Batch::new();

        remove_table(&mut batch, &table);
        send_and_process(batch.finalize()).await?;

        log::info!("Kill switch disabled");

        Ok(())
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
    CString::new(iface)
        .map_err(|_| Error::InvalidInterfaceName(iface.to_owned()))
}

#[cfg(test)]
mod tests {
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

        assert!(matches!(err, Error::InvalidInterfaceName(_)));
    }
}
