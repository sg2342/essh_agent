-module(essh_agents).

-behaviour(gen_statem).

-export([init/1, handle_event/4, callback_mode/0]).

-export([start_link/0]).
-export([req/2]).

-include("essh_binary.hrl").
-include("essh_agent_constants.hrl").

-type essh_certificate() :: essh_pkt:essh_certificate().
-type essh_public_key() :: essh_pkt:essh_public_key().
-type essh_private_key() :: essh_pkt:essh_private_key().
-type essh_constraints() :: essh_pkt:essh_constraints().

-record(t,{pubOrCert :: essh_public_key() | essh_certificate(),
	   priv :: essh_private_key(),
	   comment :: binary(),
	   constraints :: essh_constraints()}).

start_link() -> gen_statem:start_link(?MODULE, [], []).

init([]) -> {ok, unlocked, []}.


callback_mode() -> handle_event_function.


-spec req(pid(), binary()) -> binary().
req(Pid, Req) when is_pid(Pid), is_binary(Req) ->
    try req1(Pid, Req) catch _:_ -> <<?BYTE(?SSH_AGENT_FAILURE)>> end.

req1(Pid, <<?BYTE(?SSH_AGENTC_REQUEST_IDENTITIES)>>) ->
    {ok, Ids} = gen_statem:call(Pid, list),
    <<?BYTE(?SSH_AGENT_IDENTITIES_ANSWER),
      (essh_pkt:enc_identities_answer(Ids))/binary>>;
req1(Pid, <<?BYTE(?SSH_AGENTC_SIGN_REQUEST),
	    ?BINARY(KeyOrCertBlob, _KeyOrCertBlobLen),
	    ?BINARY(TBS, _TBSLen),
	    ?UINT32(_Flags)>>) ->
    KeyOrCert = essh_pkt:dec_key_or_cert(KeyOrCertBlob),
    {ok, {SignInfo, Signature}} =
	gen_statem:call(Pid, {sign_request, KeyOrCert, TBS}),
    SignatureBlob = <<?BINARY(SignInfo), ?BINARY(Signature)>>,
    <<?BYTE(?SSH_AGENT_SIGN_RESPONSE), ?BINARY(SignatureBlob)>>;
req1(Pid, <<?BYTE(?SSH_AGENTC_ADD_IDENTITY), Req/binary>>) ->
    {PubOrCert, Priv, Comment, []} = essh_pkt:dec_add_id(Req),
    req2(gen_statem:call(Pid, {add, #t{pubOrCert = PubOrCert,
				       priv = Priv,
				       comment = Comment,
				       constraints = []}}));
req1(Pid, <<?BYTE(?SSH_AGENTC_REMOVE_IDENTITY),
	    ?BINARY(KeyOrCertBlob, _KeyOrCertBlobLen)>>) ->
    KeyOrCert = essh_pkt:dec_key_or_cert(KeyOrCertBlob),
    req2(gen_statem:call(Pid, {remove, KeyOrCert}));
req1(Pid, <<?BYTE(?SSH_AGENTC_REMOVE_ALL_IDENTITIES)>>) ->
    req2(gen_statem:call(Pid, remove_all));
req1(Pid, <<?BYTE(?SSH_AGENTC_ADD_ID_CONSTRAINED), Req/binary>>) ->
    {PubOrCert, Priv, Comment, Constraints} = essh_pkt:dec_add_id(Req),
    req2(gen_statem:call(Pid, {add, #t{pubOrCert = PubOrCert,
				       priv = Priv,
				       comment = Comment,
				       constraints = Constraints}}));
req1(Pid, <<?BYTE(?SSH_AGENTC_LOCK), ?BINARY(Password, _PasswordLen)>>) ->
    req2(gen_statem:call(Pid, {lock, Password}));
req1(Pid, <<?BYTE(?SSH_AGENTC_UNLOCK), ?BINARY(Password, _PasswordLen)>>) ->
    req2(gen_statem:call(Pid, {unlock, Password})).

req2(ok) -> <<?BYTE(?SSH_AGENT_SUCCESS)>>;
req2(_) -> <<?BYTE(?SSH_AGENT_FAILURE)>>.


handle_event({call, From}, list, locked, _) ->
    {keep_state_and_data, [{reply, From, {ok, []}}]};
handle_event({call, From}, list, unlocked, L) ->
    LL = [{Id, C} || #t{pubOrCert = Id, comment = C} <- L],
    {keep_state_and_data, [{reply, From, {ok, LL}}]};
handle_event({call, From}, {add, Id}, unlocked, L0) ->
    L = lists:keystore(Id#t.pubOrCert, #t.pubOrCert, L0, Id),
    {keep_state, L, [{reply, From, ok}]};
handle_event({call, From}, {sign_request, PubOrCert, TBS}, unlocked, L) ->
    R = case lists:keyfind(PubOrCert, #t.pubOrCert, L) of
	    false -> {error, no_matching_key};
	    #t{pubOrCert = #{public_key := Pub}, priv = Priv} ->
		SignInfo = essh_cert:signinfo(Pub),
		DigestType = essh_cert:digest_type(SignInfo),
		{ok, {SignInfo, essh_cert:key_sign1(TBS, DigestType, Priv)}};
	    #t{pubOrCert = Pub, priv = Priv} ->
		SignInfo = essh_cert:signinfo(Pub),
		DigestType = essh_cert:digest_type(SignInfo),
		{ok, {SignInfo, essh_cert:key_sign1(TBS, DigestType, Priv)}}
	end,
    {keep_state_and_data, [{reply, From, R}]};
handle_event({call, From}, {remove, PubOrCert}, unlocked, L0) ->
    case lists:keytake(PubOrCert, #t.pubOrCert, L0) of
	false ->
	    {keep_state_and_data, [{reply, From, {error, no_matching_key}}]};
	{value, _, L} ->
	    {keep_state, L, [{reply, From, ok}]}
    end;
handle_event({call, From}, remove_all, unlocked, _) ->
    {keep_state, [], [{reply, From, ok}]};
handle_event({call, From}, {lock, Password}, unlocked, L) ->
    {next_state, locked, {Password, L}, [{reply, From, ok}]};
handle_event({call, From}, {unlock, Password}, locked, {Password, L}) ->
    {next_state, unlocked, L, [{reply, From, ok}]};
handle_event({call, From}, _,_,_) ->
    {keep_state_and_data, [{reply, From, {error, agent_failure}}]}.
