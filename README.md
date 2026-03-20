# proton-vpn-linux

**proton-vpn-linux** is the Rust backend for ProtonVPN's Linux client. It implements a NetworkManager VPN plugin for WireGuard-based connections (protun), a local agent communication layer, and server scoring — exposing functionality to higher-level ProtonVPN tooling via both native Rust and Python (PyO3) interfaces.

# Core

## Building the python extensions
> cargo build --features 'core,python'


# Protun

## Building
> cargo build --bin nm-protun-service --bin nm-protun-auth-dialog --features 'protun, nm_protun_auth_dialog'

## Installing

Register the plugin with NetworkManager:

> sudo bash -c 'cat resources/nm-protun.name | envsubst > /usr/lib/NetworkManager/VPN/nm-protun.name'

Grant the plugin rights to the D-Bus namespace:

> sudo cp resources/nm-protun-service.conf /usr/share/dbus-1/system.d/

## Creating a connection

Use the `cli` command to generate and apply the nmcli command from a WireGuard config file:

```bash
cargo run --bin nm-protun-service --features protun -- cli --read-config /path/to/wireguard.conf | bash
nmcli connection up proton0
```

To also capture packets for debugging:

```bash
cargo run --bin nm-protun-service --features protun -- cli \
    --read-config /path/to/wireguard.conf \
    --pcap-file /tmp/capture.pcap | bash
nmcli connection up proton0
```

## Debugging

Use this command to see stdout/stderr of the plugin.

sudo journalctl -u NetworkManager.service -f -o cat

## Custom Routing

Custom routing is where we want to be before the public release.

Currently we avoid routing loop by special casing packets destined for the
vpn server, in the future we dont want to do this. Instead we want to support
an fwmark. All traffic that is the from vpn network interface should have the
fwmark.

This is not ready for testing yet, but during development this feature needs
to be enabled.

### Building
> cargo build --bin nm-protun-service --bin nm-protun-auth-dialog --features 'protun, nm_protun_auth_dialog, protun_fwmark'

### Running
> nmcli connection add type vpn vpn-type protun con-name "proton0" # Make connection
> nmcli connection modify proton0 ipv4.auto-route-ext-gw no        # Disable gateway ip routing
> nmcli connection up "proton0"                                    # Start the connection

ALternatively, perhaps we could use ipv4.method=manual to disable the routing table entries as well.
