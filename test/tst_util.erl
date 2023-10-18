-module(tst_util).

-export([
    generate_testkeys/1,
    key_names/0,
    add_openssh_key/2,
    spwn/2,
    start_openssh_agent/1,
    stop_openssh_agent/1
]).

-include_lib("common_test/include/ct.hrl").

add_openssh_key(KeyFile, Config) ->
    SockPath = ?config(agent_sock_path, Config),
    PrivDir = ?config(priv_dir, Config),
    KeyDir = ?config(key_dir, Config),
    {0, _} = spwn(
        ["ssh-add", "-q", filename:join(KeyDir, KeyFile)],
        [{"SSH_AUTH_SOCK", SockPath}, {"HOME", PrivDir}]
    ),
    ok.

-spec spwn(Args :: [string()], Env :: [{string(), string()}]) ->
    {ExitCode :: integer(), string()}.
spwn([Arg0 | Args], Env) ->
    Opts = [stream, in, eof, hide, exit_status, {arg0, Arg0}, {args, Args}, {env, Env}],
    spwn1(open_port({spawn_executable, os:find_executable(Arg0)}, Opts), []).

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

start_openssh_agent(Config) ->
    %%{ok, CWD} = file:get_cwd(),
    %%L = length(filename:split(CWD)),
    %%PD0 =  filename:split(?config(priv_dir, Config)),
    %%filename:join(lists:nthtail(L, PD0) ++ ["auth.sock"]),
    SshAuthSock = "/tmp/stop_uds_path_too_long_complaints." ++ os:getpid(),
    Pid = spawn_link(fun() -> spwn(["ssh-agent", "-D", "-a", SshAuthSock], []) end),
    Pid ! {os_pid, self()},
    OsPid =
        receive
            {os_pid, P} -> P
        end,
    timer:sleep(300),
    [{agent_sock_path, SshAuthSock}, {agent_os_pid, OsPid} | Config].

stop_openssh_agent(Config) ->
    OsPid = ?config(agent_os_pid, Config),
    {0, _} = spwn(
        ["ssh-agent", "-k"],
        [{"SSH_AGENT_PID", integer_to_list(OsPid)}]
    ),
    lists:keydelete(
        agent_sock_path,
        1,
        (lists:keydelete(agent_os_pid, 1, Config))
    ).

key_names() -> ["RSA", "DSA", "ED25519", "ECDSA", "ECDSA384", "ECDSA521"].

generate_testkeys(Dir) ->
    ok = file:make_dir(Dir),
    L0 = [
        {undefined, "rsa", "RSA"},
        {undefined, "dsa", "DSA"},
        {undefined, "ed25519", "ED25519"},
        {undefined, "ecdsa", "ECDSA"},
        {"384", "ecdsa", "ECDSA384"},
        {"521", "ecdsa", "ECDSA521"},
        {undefined, "ed25519", "id_ed25519"}
    ],
    L = [{Bits, Type, filename:join(Dir, Name)} || {Bits, Type, Name} <- L0],
    lists:foreach(fun generate_testkeys1/1, L).

generate_testkeys1({undefined, Type, OutputKeyfile}) ->
    {0, _} = tst_util:spwn(
        [
            "ssh-keygen",
            "-N",
            "",
            "-C",
            "some comment",
            "-t",
            Type,
            "-f",
            OutputKeyfile
        ],
        []
    );
generate_testkeys1({Bits, Type, OutputKeyfile}) ->
    {0, _} = tst_util:spwn(
        [
            "ssh-keygen",
            "-N",
            "",
            "-C",
            "some comment",
            "-b",
            Bits,
            "-t",
            Type,
            "-f",
            OutputKeyfile
        ],
        []
    ).
