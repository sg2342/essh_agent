-module(essh_agentc_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("public_key/include/public_key.hrl").

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
    add_smartcard_key/1,
    remove_smartcard_key/1,
    lock/1,
    add_smartcard_key_constrained/1,
    add_certificate/1,
    remove_certificate/1,
    sign_with_cert/1,
    cover1/1,
    cover2/1
]).

all() ->
    [
        request_identities,
        sign_request,
        add_identity,
        remove_identity,
        remove_all_identities,
        add_id_constrained,
        add_smartcard_key,
        remove_smartcard_key,
        lock,
        add_smartcard_key_constrained,
        add_certificate,
        remove_certificate,
        sign_with_cert,
        cover1,
        cover2
    ].

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
init_per_testcase(_TC, Config) -> tst_util:start_openssh_agent(Config).

end_per_testcase(cover1, Config) -> Config;
end_per_testcase(_TC, Config) -> tst_util:stop_openssh_agent(Config).

request_identities(Config) ->
    [] = agent_ids(Config),
    tst_util:add_openssh_key("id_ed25519", Config),
    [{_, _}, {_, _}] = agent_ids(Config).

sign_request(Config) ->
    Agent = {local, ?config(agent_sock_path, Config)},
    TBS = <<"TBS">>,
    tst_util:add_openssh_key("ED25519", Config),
    [{SignatureKey, _}] = agent_ids(Config),
    {ok, <<11:32, "ssh-ed25519", L:32, Signature:L/binary>>} =
        essh_agentc:sign_request(Agent, TBS, SignatureKey),
    true = public_key:verify(TBS, none, Signature, SignatureKey).

add_identity(Config) ->
    Agent = {local, ?config(agent_sock_path, Config)},
    Comment = <<"comment">>,
    E = 65537,
    #'RSAPrivateKey'{modulus = N} =
        RSAkey =
        public_key:generate_key({rsa, 1024, 65537}),
    ok = essh_agentc:add_identity(Agent, RSAkey, Comment),
    [{#'RSAPublicKey'{modulus = N, 'publicExponent' = E}, Comment}] =
        agent_ids(Config).

remove_identity(Config) ->
    Agent = {local, ?config(agent_sock_path, Config)},
    lists:foreach(
        fun(K) ->
            tst_util:add_openssh_key(K, Config),
            [{Key, _Comment}] = agent_ids(Config),
            ok = essh_agentc:remove_identity(Agent, Key),
            [] = agent_ids(Config)
        end,
        ["RSA", "DSA", "ECDSA", "ED25519"]
    ).

remove_all_identities(Config) ->
    tst_util:add_openssh_key("ED25519", Config),
    tst_util:add_openssh_key("ECDSA", Config),
    Agent = {local, ?config(agent_sock_path, Config)},
    [_ | _] = agent_ids(Config),
    ok = essh_agentc:remove_all_identities(Agent),
    [] = agent_ids(Config).

add_id_constrained(Config) ->
    Agent = {local, ?config(agent_sock_path, Config)},
    Comment = <<"comment">>,
    Constraints = [confirm, {lifetime, 1}],
    C = {'namedCurve', ?secp521r1},
    #'ECPrivateKey'{'publicKey' = PK} =
        ECkey =
        public_key:generate_key(C),
    ok = essh_agentc:add_id_constrained(Agent, ECkey, Comment, Constraints),
    [{{#'ECPoint'{point = PK}, C}, Comment}] = agent_ids(Config),
    timer:sleep(timer:seconds(2)),
    [] = agent_ids(Config).

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
    [{Key, Comment}] = agent_ids(Config),
    ok = essh_agentc:lock(Agent, Password),
    [] = agent_ids(Config),
    {error, agent_failure} = essh_agentc:lock(Agent, Password),
    {error, agent_failure} = essh_agentc:unlock(Agent, <<"notthepassword">>),
    ok = essh_agentc:unlock(Agent, Password),
    [{Key, Comment}] = agent_ids(Config).

add_smartcard_key_constrained(Config) ->
    Agent = {local, ?config(agent_sock_path, Config)},
    Constraints = [{<<"ext@example">>, <<"something">>}],
    {error, agent_failure} =
        essh_agentc:add_smartcard_key_constrained(
            Agent,
            <<"Id">>,
            <<"Pin">>,
            Constraints
        ).

add_certificate(Config) ->
    Agent = {local, ?config(agent_sock_path, Config)},
    KeyDir = ?config(key_dir, Config),
    [] = agent_ids(Config),
    tst_util:add_openssh_key("id_ed25519", Config),
    Cert = cert_of_ids(Agent),
    ok = essh_agentc:remove_all_identities(Agent),
    {ok, KeyBin} = file:read_file(filename:join(KeyDir, "id_ed25519")),
    [{#'ECPrivateKey'{} = Key, _}, _] = ssh_file:decode(KeyBin, openssh_key_v1),
    ok = essh_agentc:add_identity(Agent, Key, Cert, <<>>),
    Cert = cert_of_ids(Agent),
    ok = essh_agentc:remove_all_identities(Agent),
    ok = essh_agentc:add_id_constrained(Agent, Key, Cert, <<>>, [confirm]),
    Cert = cert_of_ids(Agent).

remove_certificate(Config) ->
    Agent = {local, ?config(agent_sock_path, Config)},
    [] = agent_ids(Config),
    tst_util:add_openssh_key("id_ed25519", Config),
    #{public_key := Pub} = Cert = cert_of_ids(Agent),
    ok = essh_agentc:remove_identity(Agent, Cert),
    [{Pub, _}] = agent_ids(Config),
    ok = essh_agentc:remove_identity(Agent, Pub),
    [] = agent_ids(Config).

sign_with_cert(Config) ->
    Agent = {local, ?config(agent_sock_path, Config)},
    tst_util:add_openssh_key("id_ed25519", Config),
    #{public_key := Pub} = Cert = cert_of_ids(Agent),
    ok = essh_agentc:remove_identity(Agent, Pub),
    [{Cert, _}] = agent_ids(Config),
    {ok, _} = essh_agentc:sign_request(Agent, <<>>, Cert).

cover1(_Config) ->
    NoAgent = {local, "/this/path/does/not/exist/fsj"},
    {error, enoent} = essh_agentc:request_identities(NoAgent),
    {error, enoent} = essh_agentc:lock(NoAgent, <<>>),
    C = {'namedCurve', ?secp521r1},
    #'ECPrivateKey'{'publicKey' = PK} =
        public_key:generate_key(C),
    {error, enoent} =
        essh_agentc:sign_request(NoAgent, <<>>, {#'ECPoint'{point = PK}, C}).

cover2(Config) ->
    Agent = {local, ?config(agent_sock_path, Config)},
    C = {'namedCurve', ?secp521r1},
    #'ECPrivateKey'{'publicKey' = PK} =
        public_key:generate_key(C),
    {error, agent_failure} =
        essh_agentc:sign_request(Agent, <<>>, {#'ECPoint'{point = PK}, C}),
    ok = essh_agentc:add_identity(Agent, dsa_key(Config), <<"comment">>),
    [{DSApub, _}] = agent_ids(Config),
    ok = essh_agentc:remove_identity(Agent, DSApub).

dsa_key(Config) ->
    FN = filename:join(?config(data_dir, Config), "dsa.pem"),
    {ok, PemBin} = file:read_file(FN),
    public_key:pem_entry_decode(hd(public_key:pem_decode(PemBin))).

generate_testkeys(Dir) ->
    tst_util:generate_testkeys(Dir),
    {0, _} = tst_util:spwn(
        [
            "ssh-keygen",
            "-q",
            "-s",
            filename:join(Dir, "id_ed25519"),
            "-I",
            "test.host",
            "-h",
            "-n",
            "test.host",
            "-h",
            filename:join(Dir, "id_ed25519.pub")
        ],
        []
    ),
    ok.

cert_of_ids(Agent) ->
    {ok, L} = essh_agentc:request_identities(Agent),
    [Cert | _] =
        lists:filtermap(
            fun
                ({#{cert_type := _} = C, _}) ->
                    {true, C};
                (_) ->
                    false
            end,
            L
        ),
    Cert.

agent_ids(Config) ->
    Agent = {local, ?config(agent_sock_path, Config)},
    {ok, L} = essh_agentc:request_identities(Agent),
    L.
