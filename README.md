# What is this?
This repo will contain a rust implementation of local agent + python bindings for it.

# The status
There's currently no library, just stubs.

# Getting started.

> ./ci/build-local wheel

That builds the python module.

Install local_agent to your venv with
> pip install target/*.whl

Now you're away.

```python
import proton.vpn.local_agent as local_agent
connection = local_agent.AgentConnector().connect("localhost", key, certificate)
```

# Repo structure.
The repo is split into 2 projects, these are:
- local_agent_rs : The rust library
- python-proton-vpn-local-agent : The python bindings


