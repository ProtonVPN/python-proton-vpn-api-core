# Core

## Building
> cargo build --features 'core,python'


# Protun
To test protun for linux.

Make sure the configs/current.conf symlink points to a working wireguard .conf file.

## Building
> cargo build --bin protun --features protun

## Installing

This is how the network manager
will recognise your connection type and associate it
with your service.

> sudo bash -c 'cat resources/nm-protun.name | envsubst > /usr/lib/NetworkManager/VPN/nm-protun.name'

This is what will grant your plugin the rights to the dbus
namespace, it will also ensure the plugin is started
this first time it's used.

> sudo cp resources/nm-protun-service.conf /etc/dbus-1/system.d/

## Testing
> nmcli connection add type vpn vpn-type protun con-name "proton0" # Make connection
> nmcli connection up "proton0"                                    # Start the connection

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

### Generate nmcli command from WireGuard config

You can use the `protun cli` command to generate the nmcli command from an existing WireGuard config file:

```bash
cargo run --bin protun --features protun -- cli --read-config /path/to/wireguard.conf
```

This makes it trivial to make a new connection from a wireguard config file.

## Debugging

Use this command to see stdout/stderr of the plugin.

sudo journalctl -u NetworkManager.service -f -o cat

## Custom Routing

### Building
> cargo build --bin protun --features protun protun_fwmark

### Running
> nmcli connection add type vpn vpn-type protun con-name "proton0" # Make connection
> nmcli connection modify proton0 ipv4.auto-route-ext-gw no        # Disable gateway ip routing
> nmcli connection up "proton0"                                    # Start the connection

ALternatively, perhaps we could use ipv4.method=manual to disable the routing table entries as well.
