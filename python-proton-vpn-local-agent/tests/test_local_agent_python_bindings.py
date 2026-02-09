def test_local_agent_python_bindings():
    from proton.vpn.local_agent import AgentConnection
    assert AgentConnection

    from proton.vpn.local_agent import State
    assert State.CONNECTED

    from proton.vpn.local_agent import Status
