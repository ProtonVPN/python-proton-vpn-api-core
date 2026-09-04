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
//! Two independent tables, each with three drop-by-default chains — `input`,
//! `output` and `forward` — so inbound, outbound and forwarded (e.g. from
//! VMs/containers) traffic is all blocked unless a rule allows it.
//!
//! # The kill switch: `inet proton_vpn_ks`
//!
//! [`FirewallKillSwitch::enable`] installs it, covering both address families.
//! Allowed traffic is:
//!
//! - loopback, in both directions
//! - established/related return traffic
//! - the WireGuard tunnel interface, and packets tagged with the fwmark
//! - LAN, link-local and multicast subnets
//! - NDP (IPv6 neighbor/router discovery) and DHCPv4
//! - the VPN server IP during the connecting phase, when
//!   [`FirewallConfig::server_ip`] is set
//!
//! [`FirewallKillSwitch::disable`] removes the table entirely.
//!
//! # IPv6 leak protection: `ip6 proton_vpn_ks_ipv6`
//!
//! [`FirewallKillSwitch::enable_ipv6_leak_protection`] installs a second table
//! that blocks IPv6 while leaving IPv4 untouched. Its rules are a subset of the
//! kill switch's, restricted to IPv6, plus explicit DHCPv6.
//!
//! It is separate because the client asks for it when the kill switch is
//! *off* — the minimum protection you get without one — so it has to survive
//! [`FirewallKillSwitch::disable`]. IPv6 reaches the VPN inside the IPv4
//! tunnel, so tunneled IPv6 stays permitted.
//!
//! # Both tables
//!
//! Whatever is not accepted is rejected at the end of the output and forward
//! chains, so blocked traffic fails at once instead of hanging until a timeout:
//! TCP gets an RST, anything else an ICMP no-route. The input chain drops
//! silently, to avoid advertising the host to unsolicited inbound. The chains'
//! drop policies remain as the fail-closed backstop.
//!
//! Everything here requires `CAP_NET_ADMIN` (netlink/netfilter access),
//! including [`FirewallKillSwitch::list_installed_tables`], which only reads.
//!
//! # Known limitations
//!
//! - **LAN blocking not supported.** Local-network traffic is always allowed;
//!   there is no mode that also blocks the LAN yet.
//! - **Port forwarding not supported.** Inbound connections initiated from the
//!   VPN side (e.g. ProtonVPN NAT-PMP) are dropped for now; only return
//!   traffic for connections this host started is allowed in.
//! - **No permanent mode.** The rules do not survive a reboot and nothing
//!   re-applies them at boot.

mod expr;
mod netlink;
mod rules;

use std::ffi::{CStr, CString};

use nftnl::{Batch, Chain, Hook, MsgType, Policy, ProtoFamily, Table};

use super::config::FirewallConfig;
use super::error::{ConfigError, Result};
use super::systemd;
use expr::End;
use netlink::send_and_process;

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

pub struct FirewallKillSwitch {
    boot_unit: Box<dyn systemd::BootUnit>,
}

impl Default for FirewallKillSwitch {
    fn default() -> Self {
        Self {
            boot_unit: Box::new(systemd::SystemdBootUnit),
        }
    }
}

impl FirewallKillSwitch
{
    /// Substitute the boot-persistence backend. Tests only; production goes
    /// through [`Default`].
    #[cfg(test)]
    fn with_boot_unit(boot_unit: Box<dyn systemd::BootUnit>) -> Self {
        Self { boot_unit }
    }

    /// Apply the kill switch rules, replacing any a previous call installed.
    ///
    /// Rules only, so it is safe for the boot one-shot, which runs before
    /// `dbus.service` exists. Ignores [`FirewallConfig::permanent`].
    ///
    /// Idempotent: calling it twice leaves the same rule set in place.
    pub async fn apply_rules(&mut self, config: &FirewallConfig) -> Result<()> {
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

    /// Apply the rules, then line up boot persistence with
    /// [`FirewallConfig::permanent`].
    ///
    /// Needs the system bus, so not usable at early boot — see
    /// [`Self::apply_rules`]. Rules go on first, so a failure never leaves the
    /// boot unit promising protection that was not applied.
    ///
    /// Idempotent.
    pub async fn enable(&mut self, config: &FirewallConfig) -> Result<()> {
        self.apply_rules(config).await?;
        self.persist(config.permanent).await
    }

    /// Line up boot persistence with `permanent`.
    async fn persist(&self, permanent: bool) -> Result<()> {
        if permanent {
            self.boot_unit.enable().await
        } else {
            self.boot_unit.disable().await
        }
    }

    /// Disable the kill switch by removing the nftables table.
    ///
    /// Idempotent: succeeds even when the kill switch was never enabled.
    pub async fn disable(&mut self) -> Result<()> {
        // Both run unconditionally: a boot unit that cannot be updated must
        // not leave the user stuck behind a firewall they asked to remove.
        let persisted = self.persist(false).await;
        let removed = self.remove_rules().await;

        removed.and(persisted)
    }

    /// Remove the kill switch table, leaving boot persistence alone.
    ///
    /// Idempotent: succeeds even when the kill switch was never enabled.
    pub async fn remove_rules(&mut self) -> Result<()> {
        let table = Table::new(TABLE_NAME, ProtoFamily::Inet);
        let mut batch = Batch::new();

        remove_table(&mut batch, &table);
        send_and_process(batch.finalize()).await?;

        log::info!("Kill switch rules removed");

        Ok(())
    }

    /// Enable IPv6 leak protection: block IPv6 that is not going through the
    /// tunnel, leaving IPv4 untouched.
    ///
    /// This lives in its own table because it has a lifetime independent of the
    /// full kill switch — the client asks for it precisely when the kill switch
    /// is *off*, so it has to survive [`disable`](Self::disable).
    ///
    /// Reads `tunnel_iface` and `fwmark` from `config`. The server IP does not
    /// apply: it admits the encrypted outer packets during connection setup, and
    /// those are IPv4.
    ///
    /// Idempotent: calling it twice leaves the same rule set in place.
    ///
    /// The two tables are meant to be mutually exclusive. These rules are a
    /// subset of the full kill switch's.
    pub async fn enable_ipv6_leak_protection(
        &mut self,
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

    /// The kill switch tables currently installed, in a stable order, each as
    /// `"<family> <name>"` — the form `nft list table` expects.
    ///
    /// Presence only — the names are all a table dump gives us. Reading the
    /// rules back would mean parsing every expression out of netlink, and
    /// `nft list table` already does that far better.
    ///
    /// Takes `&self` rather than `&mut self` since it changes nothing, but it
    /// still requires `CAP_NET_ADMIN`: netfilter demands it even to read.
    pub async fn list_installed_tables(&self) -> Result<Vec<String>> {
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

    /// Disable IPv6 leak protection by removing its nftables table.
    ///
    /// Idempotent: succeeds even when it was never enabled. Leaves the full kill
    /// switch table alone.
    pub async fn disable_ipv6_leak_protection(&mut self) -> Result<()> {
        let table = Table::new(IPV6_TABLE_NAME, ProtoFamily::Ipv6);
        let mut batch = Batch::new();

        remove_table(&mut batch, &table);
        send_and_process(batch.finalize()).await?;

        log::info!("IPv6 leak protection disabled");

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
    Ok(CString::new(iface)
        .map_err(|_| ConfigError::InterfaceName(iface.to_owned()))?)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use super::super::error::Error;
    use super::*;

    /// Records what `persist` asked for. Cloneable so the test keeps a handle
    /// after the kill switch takes ownership of one.
    ///
    /// Only `persist` is covered: `enable`/`disable` apply real rules, which
    /// needs `CAP_NET_ADMIN`.
    #[derive(Clone, Default)]
    struct SpyBootUnit {
        enabled: Arc<AtomicUsize>,
        disabled: Arc<AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl systemd::BootUnit for SpyBootUnit {
        async fn enable(&self) -> Result<()> {
            self.enabled.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        async fn disable(&self) -> Result<()> {
            self.disabled.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    /// (enable calls, disable calls) after one `persist`.
    async fn persist_calls(permanent: bool) -> (usize, usize) {
        let spy = SpyBootUnit::default();

        FirewallKillSwitch::with_boot_unit(Box::new(spy.clone()))
            .persist(permanent)
            .await
            .unwrap();

        (
            spy.enabled.load(Ordering::SeqCst),
            spy.disabled.load(Ordering::SeqCst),
        )
    }

    #[tokio::test]
    async fn permanent_mode_enables_the_boot_unit() {
        assert_eq!(persist_calls(true).await, (1, 0));
    }

    #[tokio::test]
    async fn non_permanent_mode_disables_the_boot_unit() {
        // Not a no-op: the user may be switching permanent off, and leaving
        // the unit enabled would resurrect the kill switch at the next boot.
        assert_eq!(persist_calls(false).await, (0, 1));
    }

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
