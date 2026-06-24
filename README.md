# Proton VPN Core API

The `proton-vpn-core-api` acts as a facade to the other Proton VPN components,
exposing a uniform API to the available Proton VPN services.

## Development

Even though our CI pipelines always test and build releases using Linux
distribution packages, you can use pip to set up your development environment.

### Proton package registry

If you didn't do it yet, to be able to pip install Proton VPN components you'll
need to set up our internal Python package registry. You can do so running the
command below, after replacing `{GITLAB_TOKEN`} with your
[personal access token](https://gitlab.protontech.ch/help/user/profile/personal_access_tokens.md)
with the scope set to `api`.

```shell
pip config set global.index-url https://__token__:{GITLAB_TOKEN}@gitlab.protontech.ch/api/v4/groups/777/-/packages/pypi/simple
```

In the index URL above, `777` is the id of the current root GitLab group,
the one containing the repositories of all our Proton VPN components.

### Known issues

This component depends on the `PyGObject` python package.

To be able to pip install `PyGObject`, please check the required distribution packages in the
[official documentation](https://pygobject.readthedocs.io/en/latest/devguide/dev_environ.html).

```shell
sudo apt install pkg-config libdbus-1-dev libglib2.0-dev
```

### Virtual environment

You can create the virtual environment and install the rest of dependencies as follows:

```shell
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

#### Rust submodule

Build the Rust binary:

```shell
cargo build --features "python,core,local_agent,protun"
```

Create a symlink to the rust binary:

```shell
ln -sf ../../target/debug/libproton_vpn_platform.so proton/vpn/platform.abi3.so
```

Then install the package in editable mode:

```shell
pip install -e .
```

After each `cargo build` the symlink automatically points to the updated `.so` —
no reinstall or re-copy needed.

### Tests

You can run the python tests with:

```shell
pytest
```

# proton-vpn-platform

**proton-vpn-platform** is the Rust backend for ProtonVPN's Linux client. It implements a NetworkManager VPN plugin for WireGuard-based connections (protun), a local agent communication layer, and server scoring — exposing functionality to higher-level ProtonVPN tooling via both native Rust and Python (PyO3) interfaces.

# Core

## Building
> cargo build --features 'core,python'

## Testing
> cargo test --features 'core,python'

# Local Agent

## Building
> cargo build --features 'local_agent'

## Testing
> cargo test --features 'local_agent'


# Protun

## Building
> cargo build --bin nm-protun-service --bin nm-protun-auth-dialog --lib --features 'protun, nm_protun_auth_dialog, python'

## Testing
> cargo test --features 'protun, nm_protun_auth_dialog, python'

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
