-module(essh_agentc_remote_SUITE).


-include_lib("common_test/include/ct.hrl").
-include_lib("public_key/include/public_key.hrl").

-export([all/0, init_per_suite/1, end_per_suite/1,
	 init_per_testcase/2, end_per_testcase/2]).

-export([host_key/2, is_auth_key/3]).
-export([request_ids/1, timeout1/1, no_agent/1]).

all() -> [request_ids, timeout1, no_agent].


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
    {ok, Connection} = receive {new_connection, C} -> {ok, C}
		       after 500 -> timeout end,
    {ok, [_|_]} = essh_agentc:request_identities({remote, Connection}),
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
    {ok, Connection} = receive {new_connection, C} -> {ok, C}
		       after 500 -> timeout end,
    {error,  {open_error,_,_,_}} = essh_agentc:request_identities({remote, Connection}),
    Openssh ! close,
    Ssh ! stop.


openssh_connection(Port, Config) ->
    SockPath = ?config(agent_sock_path, Config),
    spawn_link(fun() -> tst_util:spwn(["ssh", "-q", "-A", "-N", "-p", integer_to_list(Port),
				       "-o", "StrictHostKeyChecking=no",
				       "-o", "UserKnownHostsFile=/dev/null",
				       "user@localhost"],
				      [{"SSH_AUTH_SOCK", SockPath}])
	       end).

openssh_connection_no_agent(Port, Config) ->
    SockPath = ?config(agent_sock_path, Config),
    spawn_link(fun() -> tst_util:spwn(["ssh", "-q", "-N", "-p", integer_to_list(Port),
				       "-o", "StrictHostKeyChecking=no",
				       "-o", "UserKnownHostsFile=/dev/null",
				       "user@localhost"],
				      [{"SSH_AUTH_SOCK", SockPath}])
	       end).



generate_testkeys(Dir) ->
    ok = file:make_dir(Dir),
    {0,_} = tst_util:spwn(["ssh-keygen", "-N", "", "-C", "some comment",
			   "-t", "ecdsa", "-f", filename:join(Dir, "testkey")],[]).


start_ssh_daemon(Port, Parent) ->
    Hostkey = public_key:generate_key({namedCurve, ?secp256r1}),
    Opts = [{connectfun, fun(_, _, _) -> Parent ! {new_connection, self()} end}
	   ,{key_cb, {?MODULE, [Hostkey]}}],
    {ok, Daemon} = ssh:daemon(Port, Opts),
    receive
	stop ->
	    _ = ssh:stop_listener(Daemon),
	    ssh:stop_daemon(Daemon)
    end.


host_key(_, [{key_cb_private, [Key]}|_]) -> {ok, Key};
host_key(_,_) -> {error, no}.

is_auth_key(_,_,_) -> true.
