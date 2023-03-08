-module(essh_agentc_remote_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("public_key/include/public_key.hrl").

-export([
    all/0,
    init_per_suite/1,
    end_per_suite/1,
    init_per_testcase/2,
    end_per_testcase/2
]).

-export([host_key/2, is_auth_key/3]).
-export([request_ids/1, timeout1/1, no_agent/1, cover/1]).

all() -> [request_ids, timeout1, no_agent, cover].

init_per_suite(Config) ->
    {ok, Started} = application:ensure_all_started(ssh),
    KeyDir = filename:join(?config(priv_dir, Config), atom_to_list(?MODULE)),
    _ = generate_testkeys(KeyDir),
    [{started_applications, Started}, {key_dir, KeyDir} | Config].

end_per_suite(Config0) ->
    {value, {_, Started}, Config} = lists:keytake(started_applications, 1, Config0),
    lists:foreach(fun application:stop/1, lists:reverse(Started)),
    Config.

-spec init_per_testcase(_, _) -> any().
init_per_testcase(_TC, Config) ->
    tst_util:start_openssh_agent(Config).

end_per_testcase(_TC, Config) ->
    tst_util:stop_openssh_agent(Config).

-define(PORT, 15224).
request_ids(Config) ->
    Port = ?PORT,
    Self = self(),
    Ssh = spawn_link(fun() -> start_ssh_daemon(Port, Self) end),
    timer:sleep(500),
    tst_util:add_openssh_key("testkey", Config),
    timer:sleep(500),
    Openssh = openssh_connection(Port, Config),
    timer:sleep(500),
    {ok, Connection} =
        receive
            {new_connection, C} -> {ok, C}
        after 500 -> timeout
        end,
    {ok, [_ | _]} = essh_agentc:request_identities({remote, Connection}),
    Openssh ! close,
    Ssh ! stop.

timeout1(_Confifg) ->
    {error, timeout} = essh_agentc:request_identities({remote, self()}).

no_agent(Config) ->
    Port = ?PORT,
    Self = self(),
    Ssh = spawn_link(fun() -> start_ssh_daemon(Port, Self) end),
    timer:sleep(500),
    tst_util:add_openssh_key("testkey", Config),
    timer:sleep(500),
    Openssh = openssh_connection_no_agent(Port, Config),
    timer:sleep(500),
    {ok, Connection} =
        receive
            {new_connection, C} -> {ok, C}
        after 500 -> timeout
        end,
    {error, {open_error, _, _, _}} = essh_agentc:request_identities({remote, Connection}),
    Openssh ! close,
    Ssh ! stop.

openssh_connection(Port, Config) ->
    SockPath = ?config(agent_sock_path, Config),
    spawn_link(fun() ->
        tst_util:spwn(
            [
                "ssh",
                "-q",
                "-A",
                "-N",
                "-p",
                integer_to_list(Port),
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "UserKnownHostsFile=/dev/null",
                "user@localhost"
            ],
            [{"SSH_AUTH_SOCK", SockPath}]
        )
    end).

openssh_connection_no_agent(Port, Config) ->
    SockPath = ?config(agent_sock_path, Config),
    spawn_link(fun() ->
        tst_util:spwn(
            [
                "ssh",
                "-q",
                "-N",
                "-p",
                integer_to_list(Port),
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "UserKnownHostsFile=/dev/null",
                "user@localhost"
            ],
            [{"SSH_AUTH_SOCK", SockPath}]
        )
    end).

generate_testkeys(Dir) ->
    ok = file:make_dir(Dir),
    {0, _} = tst_util:spwn(
        [
            "ssh-keygen",
            "-N",
            "",
            "-C",
            "some comment",
            "-t",
            "ecdsa",
            "-f",
            filename:join(Dir, "testkey")
        ],
        []
    ).

start_ssh_daemon(Port, Parent) ->
    Hostkey = public_key:generate_key({namedCurve, ?secp256r1}),
    Opts = [
        {connectfun, fun(_, _, _) -> Parent ! {new_connection, self()} end},
        {key_cb, {?MODULE, [Hostkey]}}
    ],
    {ok, Daemon} = ssh:daemon(Port, Opts),
    receive
        stop ->
            _ = ssh:stop_listener(Daemon),
            ssh:stop_daemon(Daemon)
    end.

cover(_Config) ->
    F1 = fun() ->
        receive
            {'$gen_call', From1, _} ->
                gen_server:reply(From1, {ok, 23})
        end,
        receive
            {'$gen_call', From2, _} ->
                gen_server:reply(From2, {error, foo})
        end,
        receive
            {'$gen_call', From3, _} ->
                gen_server:reply(From3, ok)
        end
    end,
    {error, foo} = essh_agentc:remove_all_identities({remote, spawn(F1)}),
    F2 = fun() ->
        receive
            {'$gen_call', From1, _} ->
                gen_server:reply(From1, {ok, 23})
        end,
        receive
            {'$gen_call', From2, _} ->
                gen_server:reply(From2, ok)
        end
    end,
    {error, timeout} = essh_agentc:remove_all_identities({remote, spawn(F2)}),
    F3 = fun() ->
        receive
            {'$gen_call', {Pid, _Ref} = From1, _} ->
                gen_server:reply(From1, {ok, 23})
        end,
        receive
            {'$gen_call', From2, _} ->
                gen_server:reply(From2, ok)
        end,
        Pid ! {ssh_cm, <<"NONSENSE">>},
        receive
            {'$gen_call', From4, _} ->
                gen_server:reply(From4, ok)
        end
    end,
    {error, {unexpected, {ssh_cm, <<"NONSENSE">>}}} =
        essh_agentc:remove_all_identities({remote, spawn(F3)}),
    F4 = fun() ->
        receive
            {'$gen_call', {Pid, _Ref} = From1, _} ->
                gen_server:reply(From1, {ok, 23})
        end,
        receive
            {'$gen_call', From2, _} ->
                gen_server:reply(From2, ok)
        end,
        Pid ! {ssh_cm, self(), {data, 23, 0, <<0:32>>}},
        receive
            {'$gen_call', From4, _} ->
                gen_server:reply(From4, ok)
        end
    end,
    {error, unexpected_data} =
        essh_agentc:remove_all_identities({remote, spawn(F4)}),
    {error, unexpected_data} =
        essh_agentc:request_identities({remote, spawn(F4)}),
    {error, unexpected_data} =
        essh_agentc:sign_request(
            {remote, spawn(F4)},
            <<>>,
            {#'ECPoint'{point = <<>>}, {namedCurve, ?secp256r1}}
        ),
    F5 = fun() ->
        receive
            {'$gen_call', {Pid, _Ref} = From1, _} ->
                gen_server:reply(From1, {ok, 23})
        end,
        receive
            {'$gen_call', From2, _} ->
                gen_server:reply(From2, ok)
        end,
        Pid ! {ssh_cm, self(), {data, 23, 0, <<5:32, 12, 1:32>>}},
        receive
            {'$gen_call', From4, _} ->
                gen_server:reply(From4, ok)
        end
    end,
    {error, unexpected_data} =
        essh_agentc:request_identities({remote, spawn(F5)}),
    F6 = fun() ->
        receive
            {'$gen_call', {Pid, _Ref} = From1, _} ->
                gen_server:reply(From1, {ok, 23})
        end,
        receive
            {'$gen_call', From2, _} ->
                gen_server:reply(From2, ok)
        end,
        Pid ! {ssh_cm, self(), {data, 23, 0, <<13:32, 12, 1:32, 0:32, 0:32>>}},
        receive
            {'$gen_call', From4, _} ->
                gen_server:reply(From4, ok)
        end
    end,
    {ok, []} =
        essh_agentc:request_identities({remote, spawn(F6)}).

host_key(_, [{key_cb_private, [Key]} | _]) -> {ok, Key};
host_key(_, _) -> {error, no}.

is_auth_key(_, _, _) -> true.
