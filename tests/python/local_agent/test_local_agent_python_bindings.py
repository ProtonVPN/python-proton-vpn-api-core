def test_local_agent_python_bindings():
    import proton.vpn.platform
    local_agent = proton.vpn.platform.local_agent

    assert local_agent.AgentConnection

    assert local_agent.State.CONNECTED

    local_agent.Status
