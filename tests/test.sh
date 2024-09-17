
# Just a little utiliy script to build and run the test for connection.
set -e
export CARGO_TARGET_DIR=../../target
pushd ../python-proton-vpn-local-agent
cargo build --release
pushd
python3 test_connection.py
