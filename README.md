essh_agent
=====

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
