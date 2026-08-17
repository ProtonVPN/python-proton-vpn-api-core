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
//! The individual rules that punch holes in the drop-by-default chains.
//!
//! Every function here appends one or more `accept` rules to a batch. Order
//! matters: nftables evaluates rules within a chain top to bottom, so the
//! sequence in which [`super::enable`] calls these is significant.

use std::ffi::CStr;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnetwork::IpNetwork;
use nftnl::expr::{ct, Verdict};
use nftnl::{nft_expr, Batch, Chain, MsgType, Rule};

use super::expr::{
    check_icmpv6,
    check_iface,
    check_ip,
    check_net,
    Direction,
    End,
    IPPROTO_UDP,
    NFPROTO_IPV4,
};

const LAN_NETS: &[&str] = &[
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    // IPv4 link-local — RFC 3927: https://www.rfc-editor.org/rfc/rfc3927
    "169.254.0.0/16",
    // IPv4 multicast — RFC 5771, IANA:
    // https://www.iana.org/assignments/multicast-addresses
    "224.0.0.0/4",
    // IPv6 ULA — RFC 4193: https://www.rfc-editor.org/rfc/rfc4193
    "fc00::/7",
    // IPv6 link-local — RFC 4291 §2.5.6:
    // https://www.rfc-editor.org/rfc/rfc4291#section-2.5.6
    "fe80::/10",
    // IPv6 multicast — RFC 4291 §2.7, IANA:
    // https://www.iana.org/assignments/ipv6-multicast-addresses
    "ff00::/8",
];

// NDP (Neighbor Discovery Protocol) addresses
// ff02::2 — Router Solicitation
const NDP_ALL_ROUTERS: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 2);
// Neighbor Solicitation
const NDP_SOLICITED_NODE_MULTICAST: &str = "ff02::1:ff00:0/104";
// Neighbor Solicitation + Advertisement
const NDP_LINK_LOCAL: &str = "fe80::/10";

/// Parse one of the hardcoded subnets above.
///
/// These are compile-time constants that are covered by a unit test, so a
/// parse failure is a bug in this file rather than something a caller can
/// trigger or recover from.
fn net(cidr: &str) -> IpNetwork {
    cidr.parse()
        .unwrap_or_else(|e| panic!("invalid hardcoded subnet {cidr:?}: {e}"))
}

/// Allow all traffic on the loopback interface in both directions.
/// Without this, local DNS, IPC, and other loopback-bound services break.
pub(super) fn add_loopback_rules(
    batch: &mut Batch,
    out_chain: &Chain,
    in_chain: &Chain,
    lo_iface: &CStr,
) {
    let mut rule = Rule::new(out_chain);
    check_iface(&mut rule, Direction::Out, lo_iface);
    rule.add_expr(&Verdict::Accept);
    batch.add(&rule, MsgType::Add);

    let mut rule = Rule::new(in_chain);
    check_iface(&mut rule, Direction::In, lo_iface);
    rule.add_expr(&Verdict::Accept);
    batch.add(&rule, MsgType::Add);
}

/// Allow packets belonging to already-established or related connections.
///
/// Pass `Some(iif)` to restrict to connections arriving on a specific
/// interface (used on the forward chain for the tunnel); pass `None` to allow
/// them regardless of interface (used on the input chain, where the encrypted
/// WireGuard return traffic arrives on the physical interface). Safe in either
/// case: conntrack only marks a connection established if we already permitted
/// it outbound.
pub(super) fn add_allow_established_connections_rule(
    batch: &mut Batch,
    chain: &Chain,
    iif: Option<&CStr>,
) {
    let mut rule = Rule::new(chain);
    if let Some(iif) = iif {
        check_iface(&mut rule, Direction::In, iif);
    }
    // Load ct state into register, mask to keep only ESTABLISHED and RELATED
    // bits, then accept if any of those bits are set (result != 0).
    let mask = ct::States::ESTABLISHED.bits() | ct::States::RELATED.bits();
    rule.add_expr(&nft_expr!(ct state));
    rule.add_expr(&nft_expr!(bitwise mask mask, xor 0u32));
    rule.add_expr(&nft_expr!(cmp != 0u32));
    rule.add_expr(&Verdict::Accept);
    batch.add(&rule, MsgType::Add);
}

/// Allow NDP (Neighbor Discovery Protocol) messages needed for IPv6 to
/// function. NDP is the IPv6 equivalent of ARP — without it, IPv6 LAN
/// communication fails entirely.
///
/// Outgoing rules go on `out_chain`; incoming rules go on `in_chain`.
pub(super) fn add_ndp_rules(
    batch: &mut Batch,
    out_chain: &Chain,
    in_chain: &Chain,
) {
    let solicited_node = net(NDP_SOLICITED_NODE_MULTICAST);
    let link_local = net(NDP_LINK_LOCAL);

    // Outgoing: Router Solicitation (133) — sent to ff02::2 to discover
    // routers.
    {
        let mut rule = Rule::new(out_chain);
        check_ip(&mut rule, End::Dst, NDP_ALL_ROUTERS);
        check_icmpv6(&mut rule, 133);
        rule.add_expr(&Verdict::Accept);
        batch.add(&rule, MsgType::Add);
    }
    // Outgoing: Neighbor Solicitation (135) — sent to solicited-node
    // multicast (ARP-request equivalent).
    {
        let mut rule = Rule::new(out_chain);
        check_net(&mut rule, End::Dst, solicited_node);
        check_icmpv6(&mut rule, 135);
        rule.add_expr(&Verdict::Accept);
        batch.add(&rule, MsgType::Add);
    }
    // Outgoing: Neighbor Solicitation (135) — also sent directly to
    // link-local addresses.
    {
        let mut rule = Rule::new(out_chain);
        check_net(&mut rule, End::Dst, link_local);
        check_icmpv6(&mut rule, 135);
        rule.add_expr(&Verdict::Accept);
        batch.add(&rule, MsgType::Add);
    }
    // Outgoing: Neighbor Advertisement (136) — reply to a Neighbor
    // Solicitation.
    {
        let mut rule = Rule::new(out_chain);
        check_net(&mut rule, End::Dst, link_local);
        check_icmpv6(&mut rule, 136);
        rule.add_expr(&Verdict::Accept);
        batch.add(&rule, MsgType::Add);
    }
    // Incoming: Router Advertisement (134) — sent by routers from link-local
    // addresses.
    {
        let mut rule = Rule::new(in_chain);
        check_net(&mut rule, End::Src, link_local);
        check_icmpv6(&mut rule, 134);
        rule.add_expr(&Verdict::Accept);
        batch.add(&rule, MsgType::Add);
    }
    // Incoming: Redirect (137) — sent by routers from link-local addresses.
    {
        let mut rule = Rule::new(in_chain);
        check_net(&mut rule, End::Src, link_local);
        check_icmpv6(&mut rule, 137);
        rule.add_expr(&Verdict::Accept);
        batch.add(&rule, MsgType::Add);
    }
    // Incoming: Neighbor Solicitation (135) — from link-local addresses.
    {
        let mut rule = Rule::new(in_chain);
        check_net(&mut rule, End::Src, link_local);
        check_icmpv6(&mut rule, 135);
        rule.add_expr(&Verdict::Accept);
        batch.add(&rule, MsgType::Add);
    }
    // Incoming: Neighbor Advertisement (136) — reply, no source restriction.
    {
        let mut rule = Rule::new(in_chain);
        check_icmpv6(&mut rule, 136);
        rule.add_expr(&Verdict::Accept);
        batch.add(&rule, MsgType::Add);
    }
}

/// Allow DHCPv4 lease request/renewal traffic in both directions.
///
/// These are DHCP *client* rules: this machine asking for, and renewing, its
/// own IP lease.
///
/// TODO: add DHCPv6 — the IPv6 equivalent of the rules below. DHCPv6 uses UDP
/// port 546 on the client and 547 on the server:
///   - outgoing request:  src port 546 → dst port 547, sent to ff02::1:2 (the
///     IPv6 multicast address meaning "all DHCP servers on this link")
///   - incoming response: src port 547 → dst port 546
///
/// TODO: add DHCP *server* rules, for when this host hands out leases itself
/// instead of asking for one — e.g. it runs the DHCP server for a NAT'd
/// VM/container network. This is the mirror image of the client rules (the
/// ports swap roles):
///   - outgoing response: src port 67 → dst port 68 (this host replying to a
///     client)
///   - incoming request:  src port 68 → dst port 67, sent to the broadcast
///     address 255.255.255.255
pub(super) fn add_dhcp_rules(
    batch: &mut Batch,
    out_chain: &Chain,
    in_chain: &Chain,
) {
    // Outgoing DHCPv4 request (sport 68 → dport 67 → 255.255.255.255).
    // Clients use the broadcast address because they have no IP yet and don't
    // know the server.
    {
        let mut rule = Rule::new(out_chain);
        rule.add_expr(&nft_expr!(meta nfproto));
        rule.add_expr(&nft_expr!(cmp == NFPROTO_IPV4));
        rule.add_expr(&nft_expr!(meta l4proto));
        rule.add_expr(&nft_expr!(cmp == IPPROTO_UDP));
        // DHCP client port: always 68 per RFC 2131
        rule.add_expr(&nft_expr!(payload udp sport));
        rule.add_expr(&nft_expr!(cmp == 68u16.to_be()));
        // DHCP server port: always 67 per RFC 2131
        rule.add_expr(&nft_expr!(payload udp dport));
        rule.add_expr(&nft_expr!(cmp == 67u16.to_be()));
        // Limited broadcast destination: 255.255.255.255
        rule.add_expr(&nft_expr!(payload ipv4 daddr));
        rule.add_expr(&nft_expr!(cmp == Ipv4Addr::new(255, 255, 255, 255)));
        rule.add_expr(&Verdict::Accept);
        batch.add(&rule, MsgType::Add);
    }
    // Incoming DHCPv4 response (sport 67 -> dport 68).
    {
        let mut rule = Rule::new(in_chain);
        rule.add_expr(&nft_expr!(meta nfproto));
        rule.add_expr(&nft_expr!(cmp == NFPROTO_IPV4));
        rule.add_expr(&nft_expr!(meta l4proto));
        rule.add_expr(&nft_expr!(cmp == IPPROTO_UDP));
        // DHCP server port (source): always 67 per RFC 2131
        rule.add_expr(&nft_expr!(payload udp sport));
        rule.add_expr(&nft_expr!(cmp == 67u16.to_be()));
        // DHCP client port (destination): always 68 per RFC 2131
        rule.add_expr(&nft_expr!(payload udp dport));
        rule.add_expr(&nft_expr!(cmp == 68u16.to_be()));
        rule.add_expr(&Verdict::Accept);
        batch.add(&rule, MsgType::Add);
    }
}

/// Allow traffic to or from the LAN subnets (local network access).
///
/// Pass [`End::Dst`] for the output/forward chains (match on destination
/// address), [`End::Src`] for the input chain (match on source address).
pub(super) fn add_lan_rules(batch: &mut Batch, chain: &Chain, end: End) {
    for cidr in LAN_NETS {
        let mut rule = Rule::new(chain);
        check_net(&mut rule, end, net(cidr));
        rule.add_expr(&Verdict::Accept);
        batch.add(&rule, MsgType::Add);
    }
}

/// Allow traffic to the VPN server IP — needed during the connecting phase,
/// before the tunnel is up and WireGuard starts marking packets with the
/// fwmark.
///
/// TODO: this allows any traffic to the server IP, not just WireGuard's own
/// packets. A malicious or misconfigured app could exploit this to bypass the
/// kill switch by sending traffic directly to the VPN server IP. To fix,
/// restrict to packets that already carry the fwmark (only WireGuard sets it),
/// rejecting everything else.
pub(super) fn add_server_ip_rule(
    batch: &mut Batch,
    chain: &Chain,
    ip: IpAddr,
) {
    let mut rule = Rule::new(chain);
    check_ip(&mut rule, End::Dst, ip);
    rule.add_expr(&Verdict::Accept);
    batch.add(&rule, MsgType::Add);
}

/// Allow packets marked with the VPN fwmark.
/// WireGuard sets this mark on all its outgoing packets (tunnel + handshake).
pub(super) fn add_fwmark_rule(batch: &mut Batch, chain: &Chain, fwmark: u32) {
    let mut rule = Rule::new(chain);
    rule.add_expr(&nft_expr!(meta mark));
    rule.add_expr(&nft_expr!(cmp == fwmark));
    rule.add_expr(&Verdict::Accept);
    batch.add(&rule, MsgType::Add);
}

/// Allow all traffic routed to the VPN tunnel interface.
pub(super) fn add_tunnel_iface_rule(
    batch: &mut Batch,
    chain: &Chain,
    iface: &CStr,
) {
    let mut rule = Rule::new(chain);
    check_iface(&mut rule, Direction::Out, iface);
    rule.add_expr(&Verdict::Accept);
    batch.add(&rule, MsgType::Add);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hardcoded_subnets_are_parseable() {
        // `net` panics on a malformed CIDR, so this covers every constant
        // that the rule builders feed to it.
        for cidr in LAN_NETS {
            net(cidr);
        }
        net(NDP_SOLICITED_NODE_MULTICAST);
        net(NDP_LINK_LOCAL);
    }

    #[test]
    fn lan_nets_cover_both_address_families() {
        assert!(LAN_NETS.iter().any(|cidr| net(cidr).is_ipv4()));
        assert!(LAN_NETS.iter().any(|cidr| net(cidr).is_ipv6()));
    }
}
