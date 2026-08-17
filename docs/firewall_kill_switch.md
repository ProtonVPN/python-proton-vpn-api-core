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

## Building

Needs `libnftnl-dev` and `libmnl-dev` (`libnftnl-devel`/`libmnl-devel` on
Fedora), which provide the pkg-config files the `nftnl-sys` and `mnl-sys` build
scripts look for.

```shell
cargo build --features kill_switch --lib \
    --bin proton-vpn-kill-switch-service --bin fwks
cargo test --features kill_switch --lib
```

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
busctl call $KS Enable '(uss)' 0 "" 185.159.157.1
busctl call $KS Disable
```

Enabling it drops all non-VPN traffic, so with no tunnel up you lose WAN
access. Loopback and the LAN keep working, so a local session survives.

## Inspecting and recovering

```shell
sudo nft list table inet protonvpn_ks
sudo nft delete table inet protonvpn_ks    # escape hatch
```

## The CLI

`fwks` applies the same rules directly, without D-Bus:

```shell
sudo ./target/debug/fwks up --iface proton0 --server-ip 185.159.157.1
sudo ./target/debug/fwks down
```

Useful for checking a rule change in isolation: run both and diff
`nft list table inet protonvpn_ks`.

## Debugging

The service logs through the `log` facade. D-Bus activation starts it as a
child of dbus-daemon, so its output goes there:

```shell
journalctl -u dbus.service -f | grep me.proton.vpn.kill_switch
```

`RUST_LOG` is honoured, but note that with a wide feature set zbus's own
tracing is bridged into the logs and is noisy at `info`.

## Known gaps

- No permanent mode: nftables rules do not survive a reboot, and nothing
  re-applies them at boot. `enable(permanent=True)` raises.
- `Enable`/`Disable` are not authorized - any local user the D-Bus policy
  admits can call them. See the TODO in `src/kill_switch/dbus/interface.rs`.
- LAN blocking, port forwarding and DHCPv6 are not
  supported. See the module docs in
  `src/kill_switch/firewall_kill_switch/mod.rs`.
