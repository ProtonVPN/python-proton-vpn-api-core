# Firewall kill switch

An nftables kill switch. A privileged D-Bus service applies the rules, and the
`firewall_kill_switch` Python backend drives it.

| piece | where |
| --- | --- |
| rules and netlink | `src/kill_switch/firewall_kill_switch/` |
| D-Bus service | `src/kill_switch/dbus/`, binary `proton-vpn-kill-switch-service` |
| CLI, for trying rules without D-Bus | `src/bin/fwks/` |
| Python backend | `proton/vpn/backend/firewall_kill_switch/` |

Everything is behind the `kill_switch` cargo feature, and the Python backend is
behind the `PROTON_VPN_FEATURE_FLAG_FirewallKillSwitch` environment variable.

## Two tables

| table | family | holds |
| --- | --- | --- |
| `proton_vpn_ks` | `inet` | the full kill switch: drop by default, both address families |
| `proton_vpn_ks_ipv6` | `ip6` | IPv6 leak protection only, leaving IPv4 alone |

They are separate because their lifetimes are independent. The client asks for
IPv6 leak protection precisely when the kill switch is **off** — the minimum
protection you get without one — so it has to survive `Disable`.

Both drop by default and reject at the end of the output and forward chains, so
blocked traffic fails immediately rather than hanging until a timeout: TCP gets
an RST, everything else an ICMP no-route. The input chain stays silent, to avoid
advertising the host to unsolicited inbound.

IPv6 is routed via the VPN interface if the server supports it, so both tables
permit IPv6 on the tunnel interface.

Both also permit traffic carrying the fwmark. Split tunneling marks the traffic
it excludes from the VPN so that WireGuard leaves it alone and it goes out the
physical interface — that traffic can be IPv6, and blocking it would break the
feature.

The two are meant to be mutually exclusive, and the client never enables both.
The IPv6 leak protection rules are a subset of the full kill switch's.

## Building for development

Needs `libnftnl-dev` and `libmnl-dev` (`libnftnl-devel`/`libmnl-devel` on
Fedora), which provide the pkg-config files the `nftnl-sys` and `mnl-sys` build
scripts look for.

```shell
cargo build --features kill_switch \
    --bin proton-vpn-kill-switch-service --bin fwks
cargo test --features kill_switch --lib
```

Do not add `--lib` to that first command. `proton/vpn/platform.abi3.so` is a
symlink into `target/debug`, so it would be overwritten with a build that has no
pyo3 in it and every Python test would stop importing. Rebuild the library with
the Python features instead:

```shell
cargo build --lib --features python,core,local_agent,protun,kill_switch
```

`clippy` and `cargo test` do not emit binaries, so rebuild before running `fwks`
or you will be exercising an old one.

## Installing the service

Both files are needed: the policy lets the service own its bus name, and the
activation entry lets D-Bus start it on demand.

```shell
sudo install -m 755 target/debug/proton-vpn-kill-switch-service \
    /usr/libexec/proton-vpn-kill-switch-service
sudo install -m 644 resources/proton-vpn-kill-switch.conf \
    /usr/share/dbus-1/system.d/me.proton.vpn.kill_switch.conf
sudo install -m 644 resources/proton-vpn-kill-switch.dbus-service \
    /usr/share/dbus-1/system-services/me.proton.vpn.kill_switch.service
sudo systemctl reload dbus
```

## Calling it

The service starts on the first call, so nothing needs launching. `Enable`
takes one `(uss)` struct - fwmark, tunnel interface, server IP - where `0` and
the empty string mean "use the service defaults".

```shell
KS="me.proton.vpn.kill_switch /me/proton/vpn/kill_switch me.proton.vpn.kill_switch"

busctl introspect me.proton.vpn.kill_switch /me/proton/vpn/kill_switch
busctl call $KS Enable '(uss)' 0 "" 1.2.3.4
busctl call $KS Disable

# IPv6 leak protection, independent of the above. No arguments: the service
# supplies the fwmark and tunnel interface from its own defaults.
busctl call $KS EnableIpv6LeakProtection
busctl call $KS DisableIpv6LeakProtection
```

Enabling it drops all non-VPN traffic, so with no tunnel up you lose WAN
access. Loopback and the LAN keep working, so a local session survives.

## Disabling every backend

```shell
python3 -m proton.vpn.killswitch.disable
```

Turns off the kill switch and IPv6 leak protection of every backend registered
with `proton.loader`, not just this one, and exits non-zero if anything failed.

Run it **before uninstalling the package**. Nothing does it for you: the removal
scriptlets used to, but they also fired when the app switches between the beta
and stable repos, which uninstalls and reinstalls and so would drop the user's
kill switch mid-toggle. Until that is solved, uninstalling with the kill switch
on leaves a drop-by-default firewall and no service left able to remove it —
`nft delete table` is then the only way out.

## Inspecting and recovering

```shell
sudo ./target/debug/fwks status            # lists both tables and their rules

# Manually list the tables with
sudo nft list table inet proton_vpn_ks
sudo nft list table ip6 proton_vpn_ks_ipv6

# Manually remove them with
sudo nft delete table inet proton_vpn_ks
sudo nft delete table ip6 proton_vpn_ks_ipv6
```

## The CLI

`fwks` applies the same rules directly, without D-Bus. It is a development tool
and is not shipped in the deb or rpm.

```shell
sudo ./target/debug/fwks up --server-ip 1.2.3.4  # Optional server IP
sudo ./target/debug/fwks down

sudo ./target/debug/fwks ipv6-up   # IPv6 leak protection only
sudo ./target/debug/fwks ipv6-down

sudo ./target/debug/fwks status  # Shows the nft tables if existing
```

Every subcommand needs root, netfilter requires `CAP_NET_ADMIN` even to read.

Useful for checking a rule change in isolation: run a subcommand and diff
`fwks status` before and after. `ipv6-down` leaving `proton_vpn_ks` standing is
the quickest check that the two tables really are independent.

## Smoke testing the IPv6 rules

```shell
sudo ./scripts/probe_ipv6_leak_protection.sh
```

Checks what the IPv6 table *does*, rather than what it says: it sends probes
inside a network namespace and watches the host end of a veth pair, so a packet
seen there is a packet that escaped. IPv6 is synthetic — the `2001:db8::/32`
documentation prefix — so it runs on an IPv4-only network, and nothing it does
can touch the host's own firewall or routing.

It checks that IPv6 leaving the physical interface is blocked, and that what must
keep working still does. A baseline phase first confirms the probes escape with
no rules installed, so a broken harness cannot report a false pass.

A smoke test, not a thorough one — the header lists what it does not cover, the
main gaps being the input chain and leaks to destinations it does not probe.
Unit tests cannot replace it: `Rule::add_expr` is write-only, the only readable
artefact is raw netlink, and `mnl::Socket` is concrete, so there is nothing to
mock.

## Debugging

The service logs through the `log` facade. D-Bus activation starts it as a
child of dbus-daemon, so its output goes there:

```shell
journalctl -u dbus.service -f | grep me.proton.vpn.kill_switch
```

`RUST_LOG` is honoured, but note that with a wide feature set zbus's own
tracing is bridged into the logs and is noisy at `info`.
