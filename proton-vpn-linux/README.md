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

> sudo cp resources/nm-protun.name /usr/lib/NetworkManager/VPN/

This is what will grant your plugin the rights to the dbus
namespace, it will also ensure the plugin is started
this first time it's used.

> sudo cp resources/nm-protun-service.conf /etc/dbus-1/system.d/

## Testing
> nmcli connection add type vpn vpn-type protun con-name "proton0" # Make connection
> nmcli connection up "proton0"                                    # Start the connection

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
