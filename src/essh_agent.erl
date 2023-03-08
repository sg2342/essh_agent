-module(essh_agent).

-export([main/1]).

main([]) ->
    main([sockpath()]);
main([SockPath]) ->
    {ok, _} = application:ensure_all_started(public_key),
    {ok, Agent} = essh_agents:start_link([{confirm, fun confirm/1}]),
    MaybeLSock = gen_tcp:listen(0, [
        {ifaddr, {local, SockPath}},
        local,
        binary,
        {packet, 4},
        {active, once}
    ]),
    listen(MaybeLSock, #{sock_path => SockPath, agent => Agent}).

listen({error, _} = E, _M) ->
    logger:error("listen failed: ~p", [E]);
listen({ok, LSock}, #{sock_path := SockPath} = M) ->
    logger:notice("SSH_AUTH_SOCK=" ++ SockPath),
    ok = file:change_mode(SockPath, 8#600),
    SignalServer = erlang:whereis(erl_signal_server),
    erlang:unregister(erl_signal_server),
    erlang:register(erl_signal_server, self()),
    Signals = [
        sighup,
        sigquit,
        sigabrt,
        sigalrm,
        sigterm,
        sigusr1,
        sigusr2,
        sigchld,
        sigstop,
        sigtstp
    ],
    [os:set_signal(S, handle) || S <- Signals],
    erlang:process_flag(trap_exit, true),
    listen_loop(M#{lsock => LSock, signal_server => SignalServer}).

listen_loop(#{lsock := LSock, agent := Agent} = M) ->
    Listener = self(),
    {Connection, Ref} =
        spawn_opt(
            fun() -> connection(gen_tcp:accept(LSock), Listener, Agent) end,
            [monitor]
        ),
    receive
        {'DOWN', Ref, process, Reason} ->
            logger:error("Connection DOWN: ~p", [Reason]),
            listen_loop(M);
        {Connection, ok} ->
            erlang:demonitor(Ref, [flush]),
            listen_loop(M);
        {'EXIT', Agent, Reason} ->
            logger:error("Agent EXIT: ~p", [Reason]),
            exit(Connection, kill),
            cleanup(M);
        {'EXIT', _, Reason} ->
            logger:notice("Listener EXIT: ~p", [Reason]),
            exit(Connection, kill),
            cleanup(M);
        {notify, Signal} ->
            exit(Connection, kill),
            logger:notice("received signal: ~p", [Signal]),
            cleanup(M),
            erl_signal_server ! {notify, Signal}
    end.

cleanup(#{
    lsock := LSock,
    sock_path := SockPath,
    signal_server := SignalServer
}) ->
    gen_tcp:close(LSock),
    _ = file:delete(SockPath),
    erlang:unregister(erl_signal_server),
    erlang:register(erl_signal_server, SignalServer).

connection({ok, Sock}, Listener, Agent) ->
    Listener ! {self(), ok},
    connection_loop(Sock, Agent);
connection(_, _, _) ->
    ok.

connection_loop(S, Agent) ->
    receive
        {tcp, S, Req} ->
            ok = gen_tcp:send(S, essh_agents:req(Agent, Req)),
            ok = inet:setopts(S, [{active, once}]),
            connection_loop(S, Agent);
        {tcp_closed, S} ->
            ok;
        {tcp_error, S, _E} ->
            gen_tcp:close(S)
    end.

sockpath() ->
    TmpDir =
        case os:getenv("TMPDIR") of
            [_ | _] = D -> D;
            _ -> "/tmp/"
        end,
    filename:join(TmpDir, "essh_agent." ++ os:getpid()).

ssh_askpass() ->
    case os:getenv("SSH_ASKPASS") of
        [_ | _] = SshAskPass -> SshAskPass;
        false -> os:find_executable("ssh-askpass")
    end.

confirm({CertOrPub, Comment}) ->
    Msg = "Allow use of key " ++ binary_to_list(Comment) ++ "\n" ++ fingerprint(CertOrPub),
    {0, "\n"} == spwn([ssh_askpass(), Msg], []).

fingerprint(#{public_key := Pub}) -> fingerprint(Pub);
fingerprint(Pub) -> ssh:hostkey_fingerprint(sha256, Pub).

-spec spwn(Args :: [string()], Env :: [{string(), string()}]) ->
    {ExitCode :: integer(), string()}.
spwn([Arg0 | Args], Env) ->
    Opts = [stream, in, eof, hide, exit_status, {arg0, Arg0}, {args, Args}, {env, Env}],
    spwn1(open_port({spawn_executable, Arg0}, Opts), []).

spwn1(Port, Sofar) ->
    receive
        close ->
            Port ! {self(), close};
        {os_pid, From} ->
            From ! erlang:port_info(Port, os_pid);
        {Port, {data, Bytes}} ->
            spwn1(Port, [Sofar | Bytes]);
        {Port, eof} ->
            Port ! {self(), close},
            receive
                {Port, closed} -> true
            end,
            receive
                {'EXIT', Port, _} -> ok
            after 1 -> ok
            end,
            ExitCode =
                receive
                    {Port, {exit_status, Code}} -> Code
                end,
            {ExitCode, lists:flatten(Sofar)}
    end.
