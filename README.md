# proton-vpn-linux

**proton-vpn-linux** is the Rust backend for ProtonVPN's Linux client. It implements a NetworkManager VPN plugin for WireGuard-based connections (protun), a local agent communication layer, and server scoring — exposing functionality to higher-level ProtonVPN tooling via both native Rust and Python (PyO3) interfaces.

# Core

## Building the python extensions
> cargo build --features 'core,python'


# Protun

## Building
> cargo build --bin nm-protun-service --bin nm-protun-auth-dialog --lib --features 'protun, nm_protun_auth_dialog, python'

## Installing

Register the plugin with NetworkManager:

> sudo bash -c 'cat resources/nm-protun.name | envsubst > /usr/lib/NetworkManager/VPN/nm-protun.name'

Grant the plugin rights to the D-Bus namespace:

> sudo cp resources/nm-protun-service.conf /usr/share/dbus-1/system.d/

## Creating a connection

Use the `cli nm` command to generate and apply the nmcli command from a WireGuard config file:

```bash
cargo run --bin nm-protun-service --features protun -- cli nm --read-config /path/to/wireguard.conf | bash
nmcli connection up proton0
```

## Debugging

Use this command to see stdout/stderr of the plugin.

sudo journalctl -u NetworkManager.service -f -o cat

### Packet capture

Use the `cli protun` command to send commands to a running protun service. For example, to start and stop a packet capture:

```bash
cargo run --bin nm-protun-service --features protun -- cli protun pcap-start --file-path /tmp/capture.pcap
cargo run --bin nm-protun-service --features protun -- cli protun pcap-stop
```

