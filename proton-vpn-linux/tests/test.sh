
# Builds and runs the tests from this directory.
set -e

SCRIPT_DIR=$(dirname "$(readlink -f "$0")")

pushd $SCRIPT_DIR/../python-proton-vpn-local-agent
cargo build --release
popd

pushd $SCRIPT_DIR
./test_connection.py
./test_playback.py
./test_listener.py
popd
