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

Use the `protun cli` command to generate the nmcli command from a WireGuard config file:

```bash
cargo run --bin nm-protun-service --features protun -- cli --read-config /path/to/wireguard.conf
```

This prints the `nmcli connection add` command to stdout. Run the output to create the connection, then bring it up:

> nmcli connection up proton0

## VPN Connection Settings

The connection settings are split across two sections:

### vpn.data section

| Key | Description | Example |
|-----|-------------|---------|
| `peers` | JSON array of peer objects | `[{"id": "peer0", "endpoint": "192.168.1.100:51820", "public-key": "xTIBA..."}]` |

Each peer object in the `peers` array contains:

| Key | Description |
|-----|-------------|
| `id` | Unique identifier for the peer |
| `endpoint` | Server endpoint (IP:port) |
| `public-key` | Base64-encoded server public key |

### ipv4 section

| Key | Description | Example |
|-----|-------------|---------|
| `ipv4.addresses` | Client VPN address with prefix | `10.2.0.2/32` |
| `ipv4.dns` | DNS servers | `10.2.0.1` |

### Example using nmcli

Note: Commas in vpn.data values must be escaped with a backslash (`\,`) because nmcli uses commas as separators.

```bash
# Create the VPN connection
nmcli connection add \
    type vpn \
    vpn-type protun \
    con-name proton0 \
    ipv4.addresses "10.2.0.2/32" \
    ipv4.dns "10.2.0.1" \
    ipv4.method manual \
    vpn.data 'peers = [{"id": "peer0"\, "endpoint": "192.168.1.100:51820"\, "public-key": "xTIBA5rboUvnH4htodjb60Y7YAf21J7YQMlNGC8HQ14="}]'

# Activate the connection
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
