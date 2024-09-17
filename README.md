# What is this?
This repo contains a rust crate for communicating with a proton LocalAgent,
server, and python bindings for that crate.

## From github

> cd python-proton-vpn-local-agent
> cargo build --release
> mv target/release/libpython_proton_vpn_local_agent.so local_agent.so

The local_agent.so file is your python module.


## Internally on x86

From the root.

> ci-libraries-rust/scripts/build-python-extension x86_64-unknown-linux-gnu && ci-libraries-rust/scripts/build-wheel

That builds the python module.

Install local_agent to your venv with
> pip install python-proton-vpn-local-agent/target/*.whl

Now you're away.

```python
import proton.vpn.local_agent as local_agent
connection = local_agent.AgentConnector().connect("localhost", key, certificate)
```

# Repo structure.
The repo is split into 2 projects, these are:
- local_agent_rs : The rust library
- python-proton-vpn-local-agent : The python bindings

