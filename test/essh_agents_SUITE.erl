-module(essh_agents_SUITE).

-include_lib("public_key/include/public_key.hrl").
-include_lib("common_test/include/ct.hrl").

-export([
    all/0,
    init_per_suite/1,
    end_per_suite/1,
    init_per_testcase/2,
    end_per_testcase/2
]).

-export([
    request_identities/1,
    sign_request/1,
    add_identity/1,
    remove_identity/1,
    remove_all_identities/1,
    add_id_constrained/1,
    lock/1,
    certs/1,
    confirm/1
]).

all() ->
    [
        request_identities,
        sign_request,
        add_identity,
        remove_identity,
        remove_all_identities,
        add_id_constrained,
        lock,
        certs,
        confirm
    ].

init_per_suite(Config) ->
    {ok, Started} = application:ensure_all_started(ssh),
    [{started_applications, Started} | Config].

end_per_suite(Config0) ->
    {value, {_, Started}, Config} = lists:keytake(started_applications, 1, Config0),
    lists:foreach(fun application:stop/1, lists:reverse(Started)),
    Config.

init_per_testcase(confirm, Config) ->
    {ok, Pid} = essh_agents:start_link([{confirm, fun(_) -> false end}]),
    init_per_testcase1(Pid, Config);
init_per_testcase(_TC, Config) ->
    {ok, Pid} = essh_agents:start_link(),
    init_per_testcase1(Pid, Config).

init_per_testcase1(Pid, Config) ->
    F = fun(Req) -> {ok, essh_agents:req(Pid, Req)} end,
    [{agent, {function, F}}, {agent_pid, Pid} | Config].

end_per_testcase(_TC, Config) ->
    gen_statem:stop(?config(agent_pid, Config)),
    Config.

request_identities(Config) ->
    [] = agent_ids(Config).

sign_request(Config) ->
    Agent = ?config(agent, Config),
    Key = public_key:generate_key({'namedCurve', ?secp256r1}),
    ok = essh_agentc:add_identity(Agent, Key, <<"comment">>),
    [{Pub, <<"comment">>}] = agent_ids(Config),
    {ok, _Signature} = essh_agentc:sign_request(Agent, <<>>, Pub),
    ok = essh_agentc:remove_all_identities(Agent),
    {error, agent_failure} = essh_agentc:sign_request(Agent, <<>>, Pub).

add_identity(Config) ->
    Agent = ?config(agent, Config),
    E = 65537,
    Comment = <<"comment">>,
    #'RSAPrivateKey'{modulus = N} =
        RSAkey =
        public_key:generate_key({rsa, 1024, 65537}),
    PublicKey = #'RSAPublicKey'{modulus = N, 'publicExponent' = E},
    ok = essh_agentc:add_identity(Agent, RSAkey, Comment),
    [{PublicKey, Comment}] = agent_ids(Config),
    ok = essh_agentc:add_identity(Agent, dsa_key(Config), Comment).

remove_identity(Config) ->
    Agent = ?config(agent, Config),
    C = {'namedCurve', ?'id-Ed25519'},
    Comment = <<"comment">>,
    #'ECPrivateKey'{'publicKey' = PK} = Priv = public_key:generate_key(C),
    PublicKey = {#'ECPoint'{point = PK}, C},
    {error, agent_failure} = essh_agentc:remove_identity(Agent, PublicKey),
    ok = essh_agentc:add_identity(Agent, Priv, Comment),
    [{PublicKey, Comment}] = agent_ids(Config),
    ok = essh_agentc:remove_identity(Agent, PublicKey),
    [] = agent_ids(Config).

remove_all_identities(Config) ->
    Agent = ?config(agent, Config),
    ok = essh_agentc:remove_all_identities(Agent).

add_id_constrained(Config) ->
    Agent = ?config(agent, Config),
    Key = public_key:generate_key({'namedCurve', ?secp384r1}),
    Comment = <<"comment">>,
    Constraints = [confirm, {lifetime, 1}, {<<"foo">>, <<"bar">>}],
    ok = essh_agentc:add_id_constrained(Agent, Key, Comment, Constraints),
    [_ | _] = agent_ids(Config),
    timer:sleep(2000),
    [] = agent_ids(Config).

lock(Config) ->
    Agent = ?config(agent, Config),
    Key = public_key:generate_key({'namedCurve', ?secp521r1}),
    Comment = <<"comment">>,
    Password = <<"password">>,
    ok = essh_agentc:add_identity(Agent, Key, Comment),
    [{Pub, Comment}] = agent_ids(Config),
    {error, agent_failure} = essh_agentc:unlock(Agent, Password),
    ok = essh_agentc:lock(Agent, Password),
    [] = agent_ids(Config),
    {error, agent_failure} = essh_agentc:add_identity(Agent, Key, Comment),
    {error, agent_failure} = essh_agentc:remove_identity(Agent, Pub),
    {error, agent_failure} = essh_agentc:lock(Agent, Password),
    {error, agent_failure} = essh_agentc:unlock(Agent, <<"wrong Password">>),
    ok = essh_agentc:unlock(Agent, Password),
    [{Pub, Comment}] = agent_ids(Config).

certs(Config) ->
    Gens = [
        {rsa, 1024, 65537},
        {'namedCurve', ?'id-Ed25519'},
        {'namedCurve', ?secp256r1},
        {'namedCurve', ?secp384r1},
        {'namedCurve', ?secp521r1}
    ],
    PrivKeys = [dsa_key(Config) | [public_key:generate_key(V) || V <- Gens]],
    PubKeys = [essh_pkt:pubkey(V) || V <- PrivKeys],
    Keys = lists:zip(PrivKeys, PubKeys),
    Agent = ?config(agent, Config),
    Comment = <<"Comment">>,
    Constraints = [confirm],
    Request = #{
        serial => 42,
        cert_type => user,
        key_id => <<"foo@bar">>,
        valid_principals => [<<"foo">>],
        valid_before => 0,
        valid_after => 18446744073709551615,
        critical_options => [],
        extensions => []
    },
    lists:foreach(
        fun({Priv, Pub}) ->
            Cert = essh_cert:key_sign(Request#{public_key => Pub}, Priv),
            ok = essh_agentc:add_identity(Agent, Priv, Cert, Comment),
            ok = essh_agentc:add_id_constrained(
                Agent,
                Priv,
                Cert,
                Comment,
                Constraints
            ),
            [{Cert, Comment}] = agent_ids(Config),
            {ok, _} = essh_agentc:sign_request(Agent, <<>>, Cert),
            ok = essh_agentc:remove_identity(Agent, Cert)
        end,
        Keys
    ).

confirm(Config) ->
    Agent = ?config(agent, Config),
    Key = public_key:generate_key({'namedCurve', ?'id-Ed25519'}),
    Comment = <<"comment">>,
    Constraints = [confirm],
    ok = essh_agentc:add_id_constrained(Agent, Key, Comment, Constraints),

    [{Pub, Comment}] = agent_ids(Config),
    {error, agent_failure} = essh_agentc:sign_request(Agent, <<>>, Pub).

dsa_key(Config) ->
    FN = filename:join(?config(data_dir, Config), "dsa.pem"),
    {ok, PemBin} = file:read_file(FN),
    public_key:pem_entry_decode(hd(public_key:pem_decode(PemBin))).

agent_ids(Config) ->
    Agent = ?config(agent, Config),
    {ok, L} = essh_agentc:request_identities(Agent),
    L.
