-module(essh_agent).

-export([main/1]).


main([]) -> main([sockpath()]);
main([SockPath]) ->
    {ok, _} = application:ensure_all_started(public_key),
    {ok, Pid} = essh_agents:start_link([{confirm, fun confirm/1}]),
    listen(SockPath, Pid).


listen(SockPath, Agent) ->
    logger:notice("SSH_AUTH_SOCK="++SockPath),
    listen1(gen_tcp:listen(0,[{ifaddr,{local, SockPath}}, local, binary,
			      {packet, 4}, {active, once}]), Agent).

listen1({error, _} = E, _Agent) ->
    logger:error("listen failed: ~p",[E]);
listen1({ok, LSock}, Agent) ->
    erlang:process_flag(trap_exit, true),
    Listener = self(),
    {Pid, Ref} =
	spawn_opt(
	  fun() ->
		  {ok, Sock} = gen_tcp:accept(LSock),
		  Listener ! {self(), ok},
		  connection(Sock, Agent)
	  end, [monitor]),
    receive
	{'DOWN', Ref, process, Reason} -> logger:error("Crash: ~p", Reason);
	{Pid, ok} -> erlang:demonitor(Ref, [flush])
    end,
    listen1({ok, LSock}, Agent).


connection(S, Agent) ->
    receive
	{tcp, S, Req} ->
	    ok = gen_tcp:send(S, essh_agents:req(Agent, Req)),
	    ok = inet:setopts(S, [{active, once}]),
	    connection(S, Agent);
	{tcp_closed, S} -> ok;
	{tcp_error, S, _E} -> gen_tcp:close(S)
    end.


sockpath() ->
    TmpDir = case os:getenv("TMPDIR") of
		 [_|_] = D -> D;
		 _ -> "/tmp/" end,
    filename:join(TmpDir, "essh_agent." ++ os:getpid()).


ssh_askpass() ->
    case os:getenv("SSH_ASKPASS") of
	[_|_] = SshAskPass-> SshAskPass;
	false -> os:find_executable("ssh-askpass")
    end.


confirm({CertOrPub, Comment}) ->
    Msg = "Allow use of key " ++ binary_to_list(Comment) ++ "\n" ++ fingerprint(CertOrPub),
    {0,"\n"} == spwn([ssh_askpass(), Msg],[]).


fingerprint(#{public_key := Pub}) -> fingerprint(Pub);
fingerprint(Pub) -> ssh:hostkey_fingerprint(sha256, Pub).


-spec spwn(Args :: [string()], Env ::[{string(), string()}]) ->
	  {ExitCode :: integer(), string()}.
spwn([Arg0|Args], Env) ->
    Opts = [stream, in, eof, hide, exit_status, {arg0, Arg0}, {args, Args}, {env, Env}],
    spwn1(open_port({spawn_executable,Arg0}, Opts), []).

spwn1(Port, Sofar) ->
    receive
	close ->
	    Port ! {self(), close};
	{os_pid, From} ->
	    From ! erlang:port_info(Port, os_pid);
	{Port, {data, Bytes}} ->
	    spwn1(Port, [Sofar|Bytes]);
	{Port, eof} ->
	    Port ! {self(), close},
	    receive {Port, closed} -> true end,
	    receive {'EXIT', Port, _} -> ok after 1 -> ok end,
	    ExitCode = receive {Port, {exit_status, Code}} -> Code end,
	    {ExitCode, lists:flatten(Sofar)}
    end.
