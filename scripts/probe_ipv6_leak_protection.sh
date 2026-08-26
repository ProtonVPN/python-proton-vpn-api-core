#!/usr/bin/env bash

# Behavioural smoke test for the IPv6 leak protection table (`fwks ipv6-up`).
#
# Rules can be read back with `nft list table`, but that only confirms they are
# what we wrote. This checks what they *do*: it sends probes and watches the wire
# from outside the machine under test, which is the only way to catch a rule that
# is present but wrong.
#
# It is a smoke test, not a thorough one. Each check fires one known probe and
# looks for that exact packet, so it can only tell you whether the paths it
# thought to try behave correctly. In particular it does NOT:
#
#   - detect leaks to destinations it does not probe. The capture filters match
#     the probe's destination, because matching all IPv6 picks up the multicast
#     and neighbour discovery traffic the rules deliberately permit, and reports
#     it as a leak. A broader sweep would need to exclude ff00::/8, fe80::/10
#     and fc00::/7 — worth adding if this ever runs somewhere with realistic
#     background traffic;
#   - exercise the input chain at all. NDP, DHCPv6 and established/related
#     inbound rules are untested;
#   - resemble a real system's traffic. The namespace runs one `nc` and nothing
#     else — no DNS, NTP, mDNS or anything that might leak in practice;
#   - say anything about the full kill switch table, only this one.
#
# Everything happens inside a network namespace, so:
#   - the host firewall and routing are never touched, and a mistake here cannot
#     cut your connectivity;
#   - IPv6 is synthetic (the 2001:db8::/32 documentation prefix), so this works
#     on an IPv4-only network.
#
# Layout: two veth pairs. One stands in for the physical interface, one is named
# proton0 to stand in for the tunnel. The host ends are the vantage point — a
# packet reaching them is a packet that escaped the namespace.
#
#        host namespace                      netns
#     phys-host  2001:db8:1::1  <---->  phys-ns  2001:db8:1::2   "physical"
#     tun-host   2001:db8:2::1  <---->  proton0  2001:db8:2::2   "tunnel"
#
# Requires root (netfilter needs CAP_NET_ADMIN even to read) and tcpdump.

set -euo pipefail

NS=fwks-probe
FWKS=${FWKS:-./target/debug/fwks}

# Physical-side pair.
PHYS_HOST=phys-host
PHYS_NS=phys-ns
PHYS_NET6=2001:db8:1
PHYS_NET4=10.99.1

# Tunnel-side pair. The namespace end must be named proton0: the rules match the
# tunnel by interface name, so the name is what makes them apply.
TUN_HOST=tun-host
TUN_NS=proton0
TUN_NET6=2001:db8:2

LEAK_DEST6=2001:db8:ffff::1           # leaves via the physical interface
ALLOWED_DEST4=10.99.255.1             # leaves via the physical interface
ALLOWED_TUN_DEST6=2001:db8:2:dead::1  # leaves via the tunnel

# Split tunneling marks the traffic it excludes from the VPN so it bypasses
# WireGuard and goes out the physical interface. Must match DEFAULT_FWMARK.
FWMARK=245447468

# Polling interval, and the two deadlines expressed in ticks
TICK=0.02
READY_TICKS=250    # 5s for tcpdump to open the capture
CAPTURE_TICKS=50   # 1s to conclude that nothing arrived

failures=0

# Colour only on a terminal, so redirected output and CI logs stay clean.
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    GREEN=$'\033[32m'; RED=$'\033[31m'; RESET=$'\033[0m'
else
    GREEN=''; RED=''; RESET=''
fi

log() { printf '\n== %s\n' "$*"; }
pass() { printf '  %sPASS%s  %s\n' "$GREEN" "$RESET" "$*"; }
fail() { printf '  %sFAIL%s  %s\n' "$RED" "$RESET" "$*"; failures=$((failures + 1)); }

require_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo "This script must run as root (netfilter needs CAP_NET_ADMIN)." >&2
        exit 1
    fi
}

cleanup() {
    ip netns del "$NS" 2>/dev/null || true
    # The host ends go with the namespace, but delete them anyway in case setup
    # failed between creating the veth and moving its peer.
    ip link del "$PHYS_HOST" 2>/dev/null || true
    ip link del "$TUN_HOST" 2>/dev/null || true
}

setup() {
    cleanup
    ip netns add "$NS"

    # Create link pairs
    # phys-ns -> phys-host
    ip link add "$PHYS_HOST" type veth peer name "$PHYS_NS" netns "$NS"
    # tun-ns -> tun-host
    ip link add "$TUN_HOST" type veth peer name "$TUN_NS" netns "$NS"

    # Set the ipv4/6 address for each host interface
    # nodad stands for no duplicate address detection, so the ipv6 addr is set instantly
    ip addr add "$PHYS_NET6::1/64" dev "$PHYS_HOST" nodad
    ip addr add "$PHYS_NET4.1/24" dev "$PHYS_HOST"
    ip addr add "$TUN_NET6::1/64" dev "$TUN_HOST" nodad
    ip link set "$PHYS_HOST" up
    ip link set "$TUN_HOST" up

    # Set the address for each namespace interface
    ip -n "$NS" addr add "$PHYS_NET6::2/64" dev "$PHYS_NS" nodad
    ip -n "$NS" addr add "$PHYS_NET4.2/24" dev "$PHYS_NS"
    ip -n "$NS" addr add "$TUN_NET6::2/64" dev "$TUN_NS" nodad
    ip -n "$NS" link set lo up
    ip -n "$NS" link set "$PHYS_NS" up
    ip -n "$NS" link set "$TUN_NS" up

    # IPv6 default via the physical side: the IPv6 leak path under test.
    ip -n "$NS" route add default via "$PHYS_NET6::1" dev "$PHYS_NS"
    # Add one IPv4 route to check that the IPv6 leak protection doesn't impact IPv4 traffic.
    ip -n "$NS" route add "$ALLOWED_DEST4" via "$PHYS_NET4.1" dev "$PHYS_NS"
    # Add one IPv6 route towards the tunnel to check that IPv6 leak protection doesn't impact tunnel traffic.
    ip -n "$NS" route add "$TUN_NET6:dead::/64" via "$TUN_NET6::1" dev "$TUN_NS"
}

# Send a probe from inside the namespace while capturing on a host-side
# interface, and report whether anything arrived.
#
#   $1 interface to watch   $2 tcpdump filter   $3.. probe command
captured() {
    local iface="$1" filter="$2"
    shift 2

    local out err
    out=$(mktemp)
    err=$(mktemp)

    # Capture traffic on the host side. -c 1 exits on the first matching packet;
    # -l keeps stdout flushed, so the line is on disk even if we have to kill it.
    tcpdump -ni "$iface" -c 1 -l -Q in "$filter" >"$out" 2>"$err" &
    local capture_pid=$!

    # tcpdump writes "listening on <iface>" once the device is open and the
    # filter is installed, and stderr is unbuffered. Probing before tcpdump
    # is listening would introduce flakyness.
    local waited=0
    until grep -q 'listening on' "$err"; do
        if [ "$waited" -ge "$READY_TICKS" ] || ! kill -0 "$capture_pid" 2>/dev/null; then
            break
        fi
        sleep "$TICK"
        waited=$((waited + 1))
    done

    # Run the probe inside the namespace, in the background.
    ip netns exec "$NS" "$@" >/dev/null 2>&1 &
    local probe_pid=$!

    # tcpdump exits when the packet lands, so this loop only runs its
    # course when the packet never comes: the blocked case.
    local elapsed=0
    while kill -0 "$capture_pid" 2>/dev/null; do
        if [ "$elapsed" -ge "$CAPTURE_TICKS" ]; then
            kill "$capture_pid" 2>/dev/null || true
            break
        fi
        sleep "$TICK"
        elapsed=$((elapsed + 1))
    done
    wait "$capture_pid" 2>/dev/null || true

    # Make sure the probe is finished/killed
    kill "$probe_pid" 2>/dev/null || true
    wait "$probe_pid" 2>/dev/null || true

    local count
    count=$(grep -c . "$out" || true)  # amout of captured packets
    rm -f "$out" "$err"

    [ "$count" -gt 0 ]
}

require_root
trap cleanup EXIT
setup

log "Baseline: no IPv6 leak protection rules installed, probes should escape"

if captured "$PHYS_HOST" "ip6 and dst host $LEAK_DEST6" nc -6 -w1 "$LEAK_DEST6" 443; then
    pass "IPv6 leaves via the physical interface without IPv6 leak protection"
else
    fail "IPv6 did not leave even with no IPv6 leak protection rules: setup problem"
fi

if captured "$PHYS_HOST" "ip and dst host $ALLOWED_DEST4" nc -4 -w1 "$ALLOWED_DEST4" 443; then
    pass "IPv4 leaves via the physical interface without IPv6 leak protection"
else
    fail "IPv4 did not leave even without IPv6 leak protection rules: setup problem"
fi

log "Enabling IPv6 leak protection inside the namespace"
ip netns exec "$NS" "$FWKS" ipv6-up --iface "$TUN_NS"
ip netns exec "$NS" "$FWKS" status | sed 's/^/  /'

log "With IPv6 leak protection on"

if captured "$PHYS_HOST" "ip6 and dst host $LEAK_DEST6" nc -6 -w1 "$LEAK_DEST6" 443; then
    fail "IPv6 escaped via the physical interface with IPv6 leap protection on: IPv6 LEAK DETECTED"
else
    pass "IPv6 successfully blocked on the physical interface"
fi

if captured "$PHYS_HOST" "ip and dst host $ALLOWED_DEST4" nc -4 -w1 "$ALLOWED_DEST4" 443; then
    pass "IPv4 still flows; IPv6 leak protection left it alone"
else
    fail "IPv4 was blocked; IPv6 leak protection must not impact IPv4"
fi

if captured "$TUN_HOST" "ip6 and dst host $ALLOWED_TUN_DEST6" nc -6 -w1 "$ALLOWED_TUN_DEST6" 443; then
    pass "IPv6 over the tunnel interface is allowed"
else
    fail "IPv6 over the tunnel was blocked; IPv6 leak protection should not block it"
fi

# Same destination as the leak probe above, which was blocked — the only
# difference is the mark, so this isolates the fwmark rule. Traffic excluded
# from the VPN by split tunneling carries it and must still get out.
if captured "$PHYS_HOST" "ip6 and dst host $LEAK_DEST6" \
        ping -6 -c1 -W1 -m "$FWMARK" "$LEAK_DEST6"; then
    pass "fwmarked IPv6 is allowed out (split tunneling keeps working)"
else
    fail "fwmarked IPv6 was blocked; split tunneling would break"
fi

log "Disabling"
ip netns exec "$NS" "$FWKS" ipv6-down
ip netns exec "$NS" "$FWKS" status | sed 's/^/  /'

if captured "$PHYS_HOST" "ip6 and dst host $LEAK_DEST6" nc -6 -w1 "$LEAK_DEST6" 443; then
    pass "IPv6 leaves again after ipv6-down"
else
    fail "IPv6 still blocked after ipv6-down — the table was not removed"
fi

if [ "$failures" -eq 0 ]; then
    printf '\n%sAll smoke checks passed.%s See the header for what this does not cover.\n' \
        "$GREEN" "$RESET"
else
    printf '\n%s%s check(s) failed.%s\n' "$RED" "$failures" "$RESET"
    exit 1
fi
