# Dev environment

To test this in a python venv make sure you are already in the venv then run the following bash command.

> cargo build --release --target x86_64-unknown-linux-gnu && scripts/build_wheel.py && pip install --force target/proton_vpn_local_agent-1.*-cp312-abi3-linux_x86_64.whl

