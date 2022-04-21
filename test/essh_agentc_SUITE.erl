-module(essh_agentc_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("public_key/include/public_key.hrl").

-export([all/0, init_per_suite/1, end_per_suite/1,
	 init_per_testcase/2, end_per_testcase/2]).

-export([request_identities/1, sign_request/1, add_identity/1, remove_identity/1,
	 remove_all_identities/1, add_id_constrained/1, add_smartcard_key/1,
	 remove_smartcard_key/1, lock/1, add_smartcard_key_constrained/1,
	 add_certificate/1,
	 cover1/1, cover2/1]).

all() -> [request_identities, sign_request, add_identity, remove_identity,
	  remove_all_identities, add_id_constrained, add_smartcard_key,
	  remove_smartcard_key, lock, add_smartcard_key_constrained,
	  add_certificate,
	  cover1, cover2].


init_per_suite(Config) ->
    {ok, Started} = application:ensure_all_started(public_key),
    generate_testkeys(filename:join(?config(priv_dir, Config), ".ssh")),
    [{started_applications, Started} | Config].


end_per_suite(Config0) ->
    {value, {_, Started}, Config} = lists:keytake(started_applications, 1, Config0),
    lists:foreach(fun application:stop/1, lists:reverse(Started)),
    Config.


init_per_testcase(cover1, Config) -> Config;
init_per_testcase(_TC, Config) ->
    tst_util:start_openssh_agent(Config).


end_per_testcase(cover1, Config) -> Config;
end_per_testcase(_TC, Config) ->
    tst_util:stop_openssh_agent(Config).


request_identities(Config) ->
    Agent = {local, ?config(agent_sock_path, Config)},
    {ok, []} = essh_agentc:request_identities(Agent),
    tst_util:add_openssh_key("id_ed25519", Config),
    {ok, [{_, _}, {_,_}]} = essh_agentc:request_identities(Agent).


sign_request(Config) ->
    Agent = {local, ?config(agent_sock_path, Config)},
    TBS = <<"TBS">>,
    tst_util:add_openssh_key("ED25519", Config),
    {ok, [{SignatureKey, _}]} = essh_agentc:request_identities(Agent),
    {ok, <<11:32, "ssh-ed25519",L:32,Signature:L/binary>>} =
	essh_agentc:sign_request(Agent, TBS, SignatureKey),
    true = public_key:verify(TBS, none, Signature, SignatureKey).


add_identity(Config) ->
    Agent = {local, ?config(agent_sock_path, Config)},
    Comment = <<"comment">>,
    E = 65537,
    #'RSAPrivateKey'{modulus = N} = RSAkey =
	public_key:generate_key({rsa, 1024, 65537}),
    ok = essh_agentc:add_identity(Agent, RSAkey, Comment),
    {ok, [{#'RSAPublicKey'{ modulus = N, publicExponent = E}, Comment}]} =
	essh_agentc:request_identities(Agent).


remove_identity(Config) ->
    Agent = {local, ?config(agent_sock_path, Config)},
    lists:foreach(
      fun(K) ->
	      tst_util:add_openssh_key(K, Config),
	      {ok, [{Key, _Comment}]} = essh_agentc:request_identities(Agent),
	      ok = essh_agentc:remove_identity(Agent, Key),
	      {ok, []} = essh_agentc:request_identities(Agent)
      end, ["RSA","DSA","ECDSA","ED25519"]).


remove_all_identities(Config) ->
    tst_util:add_openssh_key("ED25519", Config),
    tst_util:add_openssh_key("ECDSA", Config),
    Agent = {local, ?config(agent_sock_path, Config)},
    {ok, [_|_]} = essh_agentc:request_identities(Agent),
    ok = essh_agentc:remove_all_identities(Agent),
    {ok, []} = essh_agentc:request_identities(Agent).


add_id_constrained(Config) ->
    Agent = {local, ?config(agent_sock_path, Config)},
    Comment = <<"comment">>,
    Constraints = [confirm, {lifetime, 1}],
    C = {namedCurve, ?'id-Ed25519'},
    #'ECPrivateKey'{publicKey = PK} = ECkey =
	public_key:generate_key(C),
    ok = essh_agentc:add_id_constrained(Agent, ECkey, Comment, Constraints),
    {ok, [{{ #'ECPoint'{point = PK}, C}, Comment}]} =
	essh_agentc:request_identities(Agent),
    timer:sleep(timer:seconds(2)),
    {ok, []} = essh_agentc:request_identities(Agent).


add_smartcard_key(Config) ->
    Agent = {local, ?config(agent_sock_path, Config)},
    {error, agent_failure} =
	essh_agentc:add_smartcard_key(Agent, <<"Id">>, <<"Pin">>).


remove_smartcard_key(Config) ->
    Agent = {local, ?config(agent_sock_path, Config)},
    {error, agent_failure} =
	essh_agentc:remove_smartcard_key(Agent, <<"Id">>),
    {error, agent_failure} =
	essh_agentc:remove_smartcard_key(Agent, <<"Id">>, <<"Pin">>).


lock(Config) ->
    Agent = {local, ?config(agent_sock_path, Config)},
    Password = <<"password">>,
    tst_util:add_openssh_key("DSA", Config),
    {error, agent_failure} = essh_agentc:unlock(Agent, Password),
    {ok, [{Key, Comment}]} = essh_agentc:request_identities(Agent),
    ok = essh_agentc:lock(Agent, Password),
    {ok, []} = essh_agentc:request_identities(Agent),
    {error, agent_failure} = essh_agentc:lock(Agent, Password),
    {error, agent_failure} = essh_agentc:unlock(Agent, <<"notthepassword">>),
    ok = essh_agentc:unlock(Agent, Password),
    {ok, [{Key, Comment}]} = essh_agentc:request_identities(Agent).


add_smartcard_key_constrained(Config) ->
    Agent = {local, ?config(agent_sock_path, Config)},
    Constraints = [{<<"ext@example">>,<<"something">>}],
    {error, agent_failure} =
	essh_agentc:add_smartcard_key_constrained(Agent, <<"Id">>, <<"Pin">>,
						  Constraints).


add_certificate(Config) ->
    Agent = {local, ?config(agent_sock_path, Config)},
    PrivDir = ?config(priv_dir, Config),
    {ok, []} = essh_agentc:request_identities(Agent),
    tst_util:add_openssh_key("id_ed25519", Config),
    CertOfIds =
	fun() ->
		{ok, L} = essh_agentc:request_identities(Agent),
		[Cert] = lists:filtermap(
			   fun({#{cert_type := _} = C, _}) -> {true, C};
			      (_) -> false
			   end, L),
		Cert
	end,
    Cert = CertOfIds(),
    ok = essh_agentc:remove_all_identities(Agent),
    {ok, KeyBin} = file:read_file(filename:join([PrivDir, ".ssh", "id_ed25519"])),
    [{#'ECPrivateKey'{} = Key, _}, _] = ssh_file:decode(KeyBin, openssh_key_v1),
    ok = essh_agentc:add_identity(Agent, Key, Cert, <<>>),
    Cert = CertOfIds(),
    ok = essh_agentc:remove_all_identities(Agent),
    ok = essh_agentc:add_id_constrained(Agent, Key, Cert, <<>>, [confirm]),
    Cert = CertOfIds().




cover1(_Config) ->
    NoAgent = {local, "/this/path/does/not/exist/fsj"},
    {error, enoent} = essh_agentc:request_identities(NoAgent),
    {error, enoent} = essh_agentc:lock(NoAgent,<<>>),
    C = {namedCurve, ?secp521r1},
    #'ECPrivateKey'{publicKey = PK}
	= public_key:generate_key(C),
    {error, enoent} =
	essh_agentc:sign_request(NoAgent, <<>>, {#'ECPoint'{point = PK}, C}).


cover2(Config) ->
    Agent = {local, ?config(agent_sock_path, Config)},
    C = {namedCurve, ?secp521r1},
    #'ECPrivateKey'{publicKey = PK}
	= public_key:generate_key(C),
    {error, agent_failure} =
	essh_agentc:sign_request(Agent, <<>>, {#'ECPoint'{point = PK}, C}),
    ok = essh_agentc:add_identity(Agent, dsa_key(Config), <<"comment">>),
    {ok, [{DSApub, _}]} = essh_agentc:request_identities(Agent),
    ok = essh_agentc:remove_identity(Agent, DSApub).


dsa_key(Config) ->
    FN = filename:join(?config(data_dir, Config), "dsa.pem"),
    {ok, PemBin} = file:read_file(FN),
    public_key:pem_entry_decode(hd(public_key:pem_decode(PemBin))).


generate_testkeys(Dir) ->
    ok = file:make_dir(Dir),
    L0 = [{undefined, "rsa", "RSA"},
	  {undefined, "dsa", "DSA"},
	  {undefined, "ed25519", "ED25519"},
	  {undefined, "ecdsa", "ECDSA"},
	  {"384", "ecdsa", "ECDSA384"},
	  {"521", "ecdsa", "ECDSA521"},
	  {undefined, "ed25519", "id_ed25519"}],
    L = [{Bits, Type, filename:join(Dir, Name)} || {Bits, Type, Name} <- L0],
    ok = lists:foreach(fun generate_testkeys1/1,L),
    {0,_} = tst_util:spwn(["ssh-keygen", "-q", "-s", filename:join(Dir, "id_ed25519"),
		  "-I", "test.host", "-h", "-n", "test.host","-h",
		  filename:join(Dir, "id_ed25519.pub")],[]),
    ok.

generate_testkeys1({undefined, Type, OutputKeyfile}) ->
    {0,_} = tst_util:spwn(["ssh-keygen", "-N", "", "-C", "some comment", "-t", Type,
		  "-f", OutputKeyfile],[]);
generate_testkeys1({Bits, Type, OutputKeyfile}) ->
    {0,_} = tst_util:spwn(["ssh-keygen", "-N", "", "-C", "some comment",
		  "-b", Bits, "-t", Type, "-f", OutputKeyfile],[]).


