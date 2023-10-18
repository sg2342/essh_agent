-module(essh_sshsig_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("public_key/include/public_key.hrl").

-export([
    all/0,
    init_per_suite/1,
    end_per_suite/1,
    init_per_testcase/2,
    end_per_testcase/2
]).

-export([key_sign/1, verify/1, agent_sign/1]).

all() -> [key_sign, verify, agent_sign].

init_per_suite(Config) ->
    {ok, Started} = application:ensure_all_started(public_key),
    KeyDir = filename:join(?config(priv_dir, Config), atom_to_list(?MODULE)),
    generate_testkeys(KeyDir),
    [{started_applications, Started}, {key_dir, KeyDir} | Config].

end_per_suite(Config0) ->
    {value, {_, Started}, Config} = lists:keytake(started_applications, 1, Config0),
    lists:foreach(fun application:stop/1, lists:reverse(Started)),
    Config.

init_per_testcase(agent_sign, Config) -> tst_util:start_openssh_agent(Config);
init_per_testcase(_TC, Config) -> Config.

end_per_testcase(agent_sign, Config) -> tst_util:stop_openssh_agent(Config);
end_per_testcase(_TC, Config) -> Config.

verify(Config) ->
    verify(tst_util:key_names(), Config).

verify([], _) ->
    ok;
verify([Name | T], Config) ->
    KeyDir = ?config(key_dir, Config),
    Data = <<"foo\n">>,
    DataFile = filename:join(?config(priv_dir, Config), "data"),
    file:write_file(DataFile, Data),
    SigFile = DataFile ++ ".sig",
    KeyFile = filename:join(KeyDir, Name),
    {0, _} = tst_util:spwn(
        ["ssh-keygen", "-Y", "sign", "-f", KeyFile, "-n", "Namespace", DataFile], []
    ),
    {ok, SigBin} = file:read_file(SigFile),
    SshSig = essh_sshsig:unarmor(SigBin),
    [{_Key, _}, {PubKey, _}] = ssh_file:decode(element(2, file:read_file(KeyFile)), openssh_key_v1),
    {PubKey, <<"Namespace">>} = essh_sshsig:verify(SshSig, Data),
    file:delete(SigFile),
    file:delete(DataFile),
    verify(T, Config).

key_sign(Config) ->
    key_sign(tst_util:key_names(), Config).

key_sign([], _) ->
    ok;
key_sign([Name | T], Config) ->
    KeyDir = ?config(key_dir, Config),
    {ok, Bin} = file:read_file(filename:join(KeyDir, Name)),
    [{Key, _}, _] = ssh_file:decode(Bin, openssh_key_v1),
    Data = <<"foo\n">>,
    SigFile = filename:join(?config(priv_dir, Config), "sig"),
    DataFile = filename:join(?config(priv_dir, Config), "data"),
    file:write_file(DataFile, Data),
    file:write_file(
        SigFile, essh_sshsig:armor(essh_sshsig:key_sign(Key, <<"Namespace">>, <<"foo\n">>))
    ),
    VerifySh = filename:join(?config(data_dir, Config), "verify.sh"),
    AllowedSignersFile = filename:join(KeyDir, "allowed_signers_file"),
    {0, _} = tst_util:spwn(
        [VerifySh, DataFile, AllowedSignersFile, Name, "Namespace", SigFile], []
    ),
    file:delete(SigFile),
    file:delete(DataFile),
    key_sign(T, Config).

agent_sign(Config) ->
    Agent = {local, ?config(agent_sock_path, Config)},
    Message = <<"foo\n">>,
    C = {'namedCurve', ?'id-Ed25519'},
    #'ECPrivateKey'{'publicKey' = PK} = SignatureKey = public_key:generate_key(C),
    PublicKey = {#'ECPoint'{point = PK}, C},
    {error, agent_failure} = essh_sshsig:agent_sign(
        PublicKey, Agent, <<"Namespace">>, Message
    ),
    ok = essh_agentc:add_identity(Agent, SignatureKey, <<"comment">>),
    {ok, SshSig256} = essh_sshsig:agent_sign(
        PublicKey, Agent, <<"Namespace">>, {sha256, crypto:hash(sha256, Message)}
    ),
    {ok, SshSig} = essh_sshsig:agent_sign(PublicKey, Agent, <<"Namespace">>, Message),
    {PublicKey, <<"Namespace">>} = essh_sshsig:verify(SshSig, Message),
    {PublicKey, <<"Namespace">>} = essh_sshsig:verify(SshSig256, Message).

generate_testkeys(Dir) ->
    tst_util:generate_testkeys(Dir),
    L = [
        [Name, " ", element(2, file:read_file(filename:join(Dir, Name ++ ".pub")))]
     || Name <- tst_util:key_names()
    ],
    file:write_file(filename:join(Dir, "allowed_signers_file"), L).
