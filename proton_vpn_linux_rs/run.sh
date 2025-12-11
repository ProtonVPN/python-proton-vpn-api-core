export RUN_LOG=info
set -e
set -u

source sourceme.sh

#cargo build --bin protun_linux --features protun_linux && sudo RUST_LOG='error' target/debug/protun_linux --wireguard-conf $PROTUN_WG_CONF --tun-interface $PROTUN_TUN_INTERFACE --default-interface $DEFAULT_INTERFACE
cargo build --bin protun_linux --features protun_linux && sudo target/debug/protun_linux --wireguard-conf $PROTUN_WG_CONF --tun-interface $PROTUN_TUN_INTERFACE --default-interface $DEFAULT_INTERFACE
