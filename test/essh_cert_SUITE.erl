-module(essh_cert_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("public_key/include/public_key.hrl").

-export([all/0, init_per_suite/1, end_per_suite/1,
	 init_per_testcase/2, end_per_testcase/2]).

-export([verify/1, verify_file/1,
	 key_sign_ed25519/1, key_sign_rsa/1, key_sign_ecdsa/1, key_sign_dsa/1,
	 agent_sign/1]).


all() ->
    [verify, verify_file,
     key_sign_ed25519, key_sign_rsa, key_sign_ecdsa, key_sign_dsa,
     agent_sign].


init_per_suite(Config) ->
    {ok, Started} = application:ensure_all_started(public_key),
    KeyDir = filename:join(?config(priv_dir, Config), atom_to_list(?MODULE)),
    generate_testkeys(KeyDir),
    [{started_applications, Started}, {key_dir, KeyDir} | Config].


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


verify(Config) ->
    Agent = {local, ?config(agent_sock_path, Config)},
    lists:foreach(
      fun(K) ->
	      tst_util:add_openssh_key(K, Config),
	      Cert = cert_of_ids(Agent),
	      true = essh_cert:verify(Cert),
	      ok = essh_agentc:remove_all_identities(Agent)
      end, ["RSA","DSA","ED25519","ECDSA","ECDSA384","ECDSA521"]).


verify_file(Config) ->
    CertFile = filename:join(?config(data_dir, Config), "rsa-cert.pub"),
    {ok, Bin} = file:read_file(CertFile),
    [_, Bin64 | _] = binary:split(Bin, <<" ">>, [global]),
    CertBlob = base64:decode(Bin64),
    Cert = essh_pkt:dec_cert(CertBlob),
    true = essh_cert:verify(Cert).


key_sign_ed25519(Config) ->
    C = {namedCurve, ?'id-Ed25519'},
    #'ECPrivateKey'{publicKey = PK} = SignatureKey = public_key:generate_key(C),
    Request = (request())#{public_key => {#'ECPoint'{point = PK}, C},
			   cert_type => user},
    Cert = essh_cert:sign(Request, SignatureKey),
    true = essh_cert:verify(Cert),
    Agent = {local, ?config(agent_sock_path, Config)},
    ok = essh_agentc:add_identity(Agent, SignatureKey, Cert, <<"comment">>),
    Cert = cert_of_ids(Agent).


key_sign_rsa(Config) ->
    E = 65537,
    #'RSAPrivateKey'{modulus = N} = SignatureKey =
	public_key:generate_key({rsa, 1024, 65537}),
    Request = (request())#{public_key => #'RSAPublicKey'{modulus = N, publicExponent = E},
			   cert_type => host},
    Cert = essh_cert:sign(Request, SignatureKey),
    true = essh_cert:verify(Cert),
    Agent = {local, ?config(agent_sock_path, Config)},
    ok = essh_agentc:add_identity(Agent, SignatureKey, Cert, <<"comment">>),
    Cert = cert_of_ids(Agent).


key_sign_ecdsa(Config) ->
    C = {namedCurve, ?secp521r1},
    #'ECPrivateKey'{publicKey = PK} = SignatureKey = public_key:generate_key(C),
    Request = (request())#{public_key => {#'ECPoint'{point = PK}, C},
			   extensions => [{<<"force-command">>, <<"/usr/bin/id">>}]},
    Cert = essh_cert:sign(Request, SignatureKey),
    true = essh_cert:verify(Cert),
    Agent = {local, ?config(agent_sock_path, Config)},
    ok = essh_agentc:add_identity(Agent, SignatureKey, Cert, <<"comment">>),
    Cert = cert_of_ids(Agent).


key_sign_dsa(Config) ->
    {ok, KeyBin} = file:read_file(filename:join(?config(key_dir, Config), "DSA")),
    [{SignatureKey, _}, {PublicKey, _}] = ssh_file:decode(KeyBin, openssh_key_v1),
    Request = (request())#{public_key => PublicKey,
			   extensions => [{<<"force-command">>, <<"/usr/bin/id">>}]},
    Cert = essh_cert:sign(Request, SignatureKey),
    true = essh_cert:verify(Cert),
    Agent = {local, ?config(agent_sock_path, Config)},
    ok = essh_agentc:add_identity(Agent, SignatureKey, Cert, <<"comment">>),
    Cert = cert_of_ids(Agent).


agent_sign(Config) ->
    C = {namedCurve, ?'id-Ed25519'},
    #'ECPrivateKey'{publicKey = PK} = SignatureKey = public_key:generate_key(C),
    PublicKey = {#'ECPoint'{point = PK}, C},
    Request = (request())#{public_key => PublicKey},
    Agent = {local, ?config(agent_sock_path, Config)},
    {error, agent_failure} = essh_cert:agent_sign(Request, Agent, PublicKey),
    ok = essh_agentc:add_identity(Agent, SignatureKey, <<"comment">>),
    {ok, Cert} = essh_cert:agent_sign(Request, Agent, PublicKey),
    true = essh_cert:verify(Cert),
    ok = essh_agentc:add_identity(Agent, SignatureKey, Cert, <<"comment">>),
    Cert = cert_of_ids(Agent).


request() ->
    #{serial => 23,
      cert_type => user,
      key_id => <<"foo@bar">>,
      valid_principals => [<<"root">>],
      valid_before => 0,
      valid_after => 18446744073709551615,
      critical_options => [],
      extensions => []}.


cert_of_ids(Agent) ->
    {ok, L} = essh_agentc:request_identities(Agent),
    [Cert| _] =
	lists:filtermap(
	  fun({#{cert_type := _} = C, _}) ->
		  {true , C};
	     (_) -> false end, L),
    Cert.


generate_testkeys(Dir) ->
    ok = file:make_dir(Dir),
    L0 = [{undefined, "rsa", "RSA"},
	  {undefined, "dsa", "DSA"},
	  {undefined, "ed25519", "ED25519"},
	  {undefined, "ecdsa", "ECDSA"},
	  {"384", "ecdsa", "ECDSA384"},
	  {"521", "ecdsa", "ECDSA521"}],
    L = [{Bits, Type, filename:join(Dir, Name)} || {Bits, Type, Name} <- L0],
    ok = lists:foreach(fun generate_testkeys1/1,L),
    lists:foreach(
      fun({_,_,K}) ->
	      {0,_} = tst_util:spwn(["ssh-keygen", "-q", "-s", filename:join(Dir, K),
				     "-I", "test.host", "-h", "-n", "test.host","-h",
				     filename:join(Dir, K ++ ".pub")],[]) end, L0),
    ok.

generate_testkeys1({undefined, Type, OutputKeyfile}) ->
    {0,_} = tst_util:spwn(["ssh-keygen", "-N", "", "-C", "some comment", "-t", Type,
			   "-f", OutputKeyfile],[]);
generate_testkeys1({Bits, Type, OutputKeyfile}) ->
    {0,_} = tst_util:spwn(["ssh-keygen", "-N", "", "-C", "some comment",
			   "-b", Bits, "-t", Type, "-f", OutputKeyfile],[]).
