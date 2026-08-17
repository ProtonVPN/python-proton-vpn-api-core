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
//! Building blocks for nftables rules.
//!
//! Each function appends the expressions that match one property of a packet
//! (interface, address, subnet, ICMPv6 type) to a rule. The rules themselves
//! are assembled in [`super::rules`].

use std::ffi::CStr;
use std::net::IpAddr;

use ipnetwork::IpNetwork;
use nftnl::expr::{
    Icmpv6HeaderField,
    InterfaceName,
    Payload,
    TransportHeaderField,
};
use nftnl::{nft_expr, Rule};

// Network protocol numbers
pub(super) const NFPROTO_IPV4: u8 = 2;
pub(super) const NFPROTO_IPV6: u8 = 10;
pub(super) const IPPROTO_UDP: u8 = 17;
pub(super) const IPPROTO_ICMPV6: u8 = 58; // RFC 4443

/// Direction of a packet relative to the host.
///
/// Used to select `meta iif` (arriving) vs `meta oif` (leaving) when matching
/// by interface.
#[derive(Copy, Clone)]
pub(super) enum Direction {
    In,
    Out,
}

/// Which end of an IP flow to match against an address or subnet.
#[derive(Copy, Clone)]
pub(super) enum End {
    Src,
    Dst,
}

/// Add an interface match expression to a rule.
///
/// [`Direction::Out`] uses `meta oifname` (outgoing interface);
/// [`Direction::In`] uses `meta iifname` (incoming interface).
///
/// Matches by name rather than index so rules can be installed before the
/// interface exists (e.g. the tunnel interface before WireGuard creates it);
/// the name is matched per packet.
pub(super) fn check_iface(
    rule: &mut Rule<'_>,
    direction: Direction,
    iface: &CStr,
) {
    rule.add_expr(&match direction {
        Direction::Out => nft_expr!(meta oifname),
        Direction::In => nft_expr!(meta iifname),
    });
    rule.add_expr(&nft_expr!(cmp == InterfaceName::Exact(iface.to_owned())));
}

/// Add a subnet match expression to a rule.
///
/// Checks nfproto, loads saddr or daddr based on `end`, applies the subnet
/// mask, and compares.
pub(super) fn check_net(rule: &mut Rule<'_>, end: End, net: IpNetwork) {
    rule.add_expr(&nft_expr!(meta nfproto));
    rule.add_expr(&nft_expr!(cmp == match net {
        IpNetwork::V4(_) => NFPROTO_IPV4,
        IpNetwork::V6(_) => NFPROTO_IPV6,
    }));
    rule.add_expr(&match (end, net) {
        (End::Src, IpNetwork::V4(_)) => nft_expr!(payload ipv4 saddr),
        (End::Src, IpNetwork::V6(_)) => nft_expr!(payload ipv6 saddr),
        (End::Dst, IpNetwork::V4(_)) => nft_expr!(payload ipv4 daddr),
        (End::Dst, IpNetwork::V6(_)) => nft_expr!(payload ipv6 daddr),
    });
    // Mask + compare: implements subnet matching.
    // bitwise computes (addr & mask) ^ xor. The xor 0 is a no-op required by
    // the API — the effective operation is just AND with the subnet mask to
    // strip the host bits.
    match net {
        IpNetwork::V4(_) => {
            rule.add_expr(&nft_expr!(bitwise mask net.mask(), xor 0u32))
        }
        IpNetwork::V6(_) => rule.add_expr(
            &nft_expr!(bitwise mask net.mask(), xor &[0u16; 8][..]),
        ),
    }
    rule.add_expr(&nft_expr!(cmp == net.ip()));
}

/// Add a specific IP address match expression to a rule.
///
/// Checks nfproto, loads saddr or daddr based on `end`, and compares to the
/// address.
pub(super) fn check_ip(
    rule: &mut Rule<'_>,
    end: End,
    ip: impl Into<IpAddr>,
) {
    let ip = ip.into();
    rule.add_expr(&nft_expr!(meta nfproto));
    rule.add_expr(&nft_expr!(cmp == match ip {
        IpAddr::V4(_) => NFPROTO_IPV4,
        IpAddr::V6(_) => NFPROTO_IPV6,
    }));
    rule.add_expr(&match (end, ip) {
        (End::Src, IpAddr::V4(_)) => nft_expr!(payload ipv4 saddr),
        (End::Src, IpAddr::V6(_)) => nft_expr!(payload ipv6 saddr),
        (End::Dst, IpAddr::V4(_)) => nft_expr!(payload ipv4 daddr),
        (End::Dst, IpAddr::V6(_)) => nft_expr!(payload ipv6 daddr),
    });
    match ip {
        IpAddr::V4(addr) => rule.add_expr(&nft_expr!(cmp == addr)),
        IpAddr::V6(addr) => rule.add_expr(&nft_expr!(cmp == addr)),
    }
}

/// Add an ICMPv6 type match expression to a rule.
///
/// Checks l4proto == ICMPv6 (58), then compares the ICMPv6 message type
/// field. No nfproto check needed — IPPROTO_ICMPV6 (58) is IPv6-only.
///
/// TODO: also match the ICMPv6 code byte, not just the type. Every ICMPv6
/// message has a type (what kind of message) and a code (a sub-type within
/// it). The NDP messages we allow are all defined to use code 0, so matching
/// code == 0 would admit only well-formed NDP. As written we accept any code
/// for a given type, so a malformed packet (e.g. type 135 with a non-zero
/// code) passes the firewall — harmless in practice (the kernel discards it),
/// just less precise. Fix: add a `code: u8` parameter, compare the
/// Icmpv6HeaderField::Code field against it, and pass 0 at every (NDP) call
/// site.
pub(super) fn check_icmpv6(rule: &mut Rule<'_>, icmpv6_type: u8) {
    rule.add_expr(&nft_expr!(meta l4proto));
    rule.add_expr(&nft_expr!(cmp == IPPROTO_ICMPV6));
    rule.add_expr(&Payload::Transport(TransportHeaderField::Icmpv6(
        Icmpv6HeaderField::Type,
    )));
    rule.add_expr(&nft_expr!(cmp == icmpv6_type));
}
