#!/usr/bin/env bash

# Behavioural smoke test for the kill switch's DHCP *server* rules (`fwks up`).
#
# With the kill switch on, a NAT'd VM must still be able to get a lease from a
# DHCP server running on this host (libvirt's default network runs dnsmasq on
# virbr0). The request is a broadcast from 0.0.0.0, which the LAN rules don't
# cover, and the reply is a broadcast if the client asks for one. This checks
# that a real client gets a lease both ways, and that the new rules did not
# open anything beyond the broadcast address.
#
# It is a smoke test, not a thorough one. It does NOT:
#
#   - cover DHCP servers that use raw packet sockets (ISC dhcpd, Kea). Those
#     bypass netfilter, so the kill switch never affected them;
#   - check that the VM's traffic then goes through the tunnel. Forwarding is
#     governed by other rules and isn't what this change touched;
#   - say anything about the IPv6 leak protection table, which is ip6-only.
#
# Everything happens inside two network namespaces, so the host firewall and
# routing are never touched:
#
#        fwks-dhcp-host                      fwks-dhcp-vm
#     br-host  10.99.3.1/24  <---------->  vm-eth  203.0.113.1/24
#     kill switch + dnsmasq                udhcpc
#
# The "host" plays the machine running the VPN, the "vm" plays the guest. The
# vm's address is only used by the negative probes, as a non-LAN peer: udhcpc
# works over a raw socket and ignores it.
#
# Requires root (netfilter needs CAP_NET_ADMIN even to read), dnsmasq, busybox
# (for udhcpc) and python3.

set -euo pipefail

HOST_NS=fwks-dhcp-host
VM_NS=fwks-dhcp-vm
FWKS=${FWKS:-./target/debug/fwks}

HOST_IFACE=br-host
VM_IFACE=vm-eth
HOST_ADDR=10.99.3.1
LEASE_RANGE=10.99.3.100,10.99.3.150
# Outside every LAN range, so the LAN rules can't be what lets it through.
NON_LAN_ADDR=203.0.113.1

DHCP_CLIENT_PORT=68
DHCP_SERVER_PORT=67

# How long a listener waits for a probe before concluding it was blocked.
LISTEN_TIMEOUT=1

failures=0
work=
dhcp_server_pid=

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
    stop_dhcp_server
    ip netns del "$HOST_NS" 2>/dev/null || true
    ip netns del "$VM_NS" 2>/dev/null || true
    if [ -n "$work" ]; then
        rm -rf "$work"
        work=
    fi
}

setup() {
    cleanup
    work=$(mktemp -d)

    ip netns add "$HOST_NS"
    ip netns add "$VM_NS"
    ip -n "$HOST_NS" link add "$HOST_IFACE" type veth peer name "$VM_IFACE" netns "$VM_NS"

    ip -n "$HOST_NS" addr add "$HOST_ADDR/24" dev "$HOST_IFACE"
    ip -n "$HOST_NS" link set lo up
    ip -n "$HOST_NS" link set "$HOST_IFACE" up
    # Lets the host reach the non-LAN peer, for the outgoing negative probe.
    ip -n "$HOST_NS" route add "$NON_LAN_ADDR/32" dev "$HOST_IFACE"

    ip -n "$VM_NS" addr add "$NON_LAN_ADDR/24" dev "$VM_IFACE"
    ip -n "$VM_NS" link set lo up
    ip -n "$VM_NS" link set "$VM_IFACE" up
    ip -n "$VM_NS" route add "$HOST_ADDR/32" dev "$VM_IFACE"
}

start_dhcp_server() {
    # The server is dnsmasq, the same one libvirt runs for its NAT networks, so
    # the test sees what a real VM setup does. dnsmasq is both a DNS and a DHCP
    # server; only DHCP is enabled here (--port=0 turns DNS off). --no-ping
    # skips the address-in-use check, which would only slow each lease down.
    #
    # Without --keep-in-foreground dnsmasq runs as a daemon, and the command only
    # returns once the server is listening, or fails with the reason.
    ip netns exec "$HOST_NS" dnsmasq --conf-file=/dev/null \
        --port=0 --interface="$HOST_IFACE" --bind-interfaces --no-ping \
        --dhcp-range="$LEASE_RANGE,1h" --dhcp-leasefile="$work/leases" \
        --pid-file="$work/dnsmasq.pid" --user=root --group=root \
        --log-facility="$work/dnsmasq.log"
    dhcp_server_pid=$(cat "$work/dnsmasq.pid")
}

stop_dhcp_server() {
    if [ -n "$dhcp_server_pid" ]; then
        kill "$dhcp_server_pid" 2>/dev/null || true
        # Not our child (it daemonised), so `wait` can't be used. Wait until
        # it's gone so port 67 is free for the listener that follows.
        while kill -0 "$dhcp_server_pid" 2>/dev/null; do sleep 0.02; done
        dhcp_server_pid=
    fi
}

# Ask for a lease from the vm namespace. Extra arguments go to udhcpc.
#
# -s /bin/true stops udhcpc configuring the interface: getting the lease is the
# whole test.
leased() {
    ip netns exec "$VM_NS" busybox udhcpc -i "$VM_IFACE" -f -q -n \
        -t 3 -T 1 -s /bin/true "$@" >/dev/null 2>&1
}

# Wait for one UDP datagram on a port, in a namespace. Succeeds if one arrives
# within LISTEN_TIMEOUT, fails otherwise.
#
# Creates ready_file once listening, so the caller knows when it is safe to
# send: a datagram sent before then would be lost and look like a block.
udp_listen_once() {
    local ns="$1" port="$2" ready_file="$3"

    ip netns exec "$ns" python3 -c '
import pathlib, socket, sys
port, ready_file, timeout = int(sys.argv[1]), sys.argv[2], float(sys.argv[3])

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("", port))
pathlib.Path(ready_file).touch()
s.settimeout(timeout)
try:
    s.recvfrom(64)
except socket.timeout:
    sys.exit(1)
' "$port" "$ready_file" "$LISTEN_TIMEOUT"
}

# Send one UDP datagram from a given source address and port, in a namespace.
#
# Never fails: when the kill switch rejects the send, the error is expected,
# and whether the datagram arrived is for the listener to say.
udp_send_from() {
    local ns="$1" src_addr="$2" src_port="$3" dst_addr="$4" dst_port="$5"

    ip netns exec "$ns" python3 -c '
import socket, sys
src_addr, src_port = sys.argv[1], int(sys.argv[2])
dst_addr, dst_port = sys.argv[3], int(sys.argv[4])

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((src_addr, src_port))
try:
    s.sendto(b"probe", (dst_addr, dst_port))
except OSError:
    pass
' "$src_addr" "$src_port" "$dst_addr" "$dst_port" || true
}

# Send one UDP datagram and report whether it got through to the receiver.
# Nothing else may be listening on the destination port.
probe_arrives() {
    local receiver_ns="$1" sender_ns="$2"
    local src_addr="$3" src_port="$4" dst_addr="$5" dst_port="$6"
    local ready_file="$work/listener.ready"
    rm -f "$ready_file"

    # 1. Start listening on the receiving side, in the background.
    udp_listen_once "$receiver_ns" "$dst_port" "$ready_file" &
    local listener_pid=$!

    # 2. Wait until it's listening (or has died, e.g. the port was taken).
    until [ -e "$ready_file" ]; do
        kill -0 "$listener_pid" 2>/dev/null || break
        sleep 0.02
    done

    # 3. Send the probe.
    udp_send_from "$sender_ns" "$src_addr" "$src_port" "$dst_addr" "$dst_port"

    # 4. The listener's result is ours: it succeeds only if the probe arrived.
    wait "$listener_pid"
}

# The two probes the new rules must not let through: DHCP-shaped traffic that
# isn't a broadcast, to or from an address outside the LAN ranges.
outgoing_unicast_arrives() {
    #             receiver  sender     source address and port      destination address and port
    probe_arrives "$VM_NS" "$HOST_NS" 0.0.0.0 "$DHCP_SERVER_PORT" "$NON_LAN_ADDR" "$DHCP_CLIENT_PORT"
}

incoming_unicast_arrives() {
    #             receiver    sender   source address and port             destination address and port
    probe_arrives "$HOST_NS" "$VM_NS" "$NON_LAN_ADDR" "$DHCP_CLIENT_PORT" "$HOST_ADDR" "$DHCP_SERVER_PORT"
}

require_root
trap cleanup EXIT
setup

log "Baseline: no kill switch, everything should get through"

if outgoing_unicast_arrives; then
    pass "unicast port 67 -> non-LAN port 68 leaves the host"
else
    fail "unicast port 67 -> non-LAN port 68 blocked with no kill switch: setup problem"
fi

if incoming_unicast_arrives; then
    pass "unicast from non-LAN port 68 -> port 67 reaches the host"
else
    fail "unicast from non-LAN port 68 -> port 67 blocked with no kill switch: setup problem"
fi

start_dhcp_server
if leased; then
    pass "vm gets a lease"
else
    fail "vm got no lease with no kill switch: setup problem"
fi
stop_dhcp_server

log "Enabling the kill switch inside the host namespace"
ip netns exec "$HOST_NS" "$FWKS" up
ip netns exec "$HOST_NS" "$FWKS" status | sed 's/^/  /'

log "With the kill switch on"

start_dhcp_server
# Without -B dnsmasq replies unicast to the offered address, which the LAN
# rules allow; this exercises the incoming broadcast request.
if leased; then
    pass "vm gets a lease (unicast reply)"
else
    fail "vm got no lease: the broadcast request was blocked"
fi

# -B asks for a broadcast reply, which also needs the outgoing broadcast rule.
if leased -B; then
    pass "vm gets a lease (broadcast reply)"
else
    fail "vm got no lease with -B: the broadcast reply was blocked"
fi
# Frees port 67 for the listener below.
stop_dhcp_server

if outgoing_unicast_arrives; then
    fail "unicast port 67 -> non-LAN port 68 escaped: the server rule is too broad"
else
    pass "unicast port 67 -> non-LAN port 68 blocked"
fi

if incoming_unicast_arrives; then
    fail "unicast from non-LAN port 68 -> port 67 got in: the server rule is too broad"
else
    pass "unicast from non-LAN port 68 -> port 67 blocked"
fi

log "Disabling"
ip netns exec "$HOST_NS" "$FWKS" down

if [ "$failures" -eq 0 ]; then
    printf '\n%sAll smoke checks passed.%s See the header for what this does not cover.\n' \
        "$GREEN" "$RESET"
else
    printf '\n%s%s check(s) failed.%s\n' "$RED" "$failures" "$RESET"
    exit 1
fi
