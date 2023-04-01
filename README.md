essh_agent
=====
[![Build Status](https://github.com/sg2342/essh_agent/workflows/Common%20Test/badge.svg)](https://github.com/sg2342/essh_agent/actions?query=branch%3Amain+workflow%3A"Common+Test")

 * SSH authentication agent implementation: [essh_agents.erl](src/essh_agents.erl)
 
 * escript code to start the agent: [essh_agent.erl](src/essh_agent.erl)
 
 * interact with local (UNIX-domain socket) and remote (ssh-connection) agents: [essh_agentc.erl](src/essh_agentc.erl)


Build
-----

    $ rebar3 compile


Build essh_agent escript
-----

    $ rebar3 escriptize


Test
----

    $ ERL_AFLAGS="-enable-feature maybe_expr" rebar3 as test check
