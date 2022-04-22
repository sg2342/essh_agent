-module(essh_agentc).

-export([request_identities/1,
	 sign_request/3,
	 add_identity/3,
	 add_identity/4,
	 remove_identity/2,
	 remove_all_identities/1,
	 add_id_constrained/4,
	 add_id_constrained/5,
	 add_smartcard_key/3,
	 remove_smartcard_key/2,
	 remove_smartcard_key/3,
	 lock/2,
	 unlock/2,
	 add_smartcard_key_constrained/4] ).

-include("essh_binary.hrl").
-include("essh_agent_constants.hrl").

-type essh_agent() :: {local, SshAuthSock :: file:name_all()} |
		      {remote, SshConnection :: pid()}.
-type essh_constraint() :: essh_pkt:essh_constraint().
-type essh_public_key() :: essh_pkt:essh_public_key().
-type essh_private_key() :: essh_pkt:essh_private_key().
-type essh_certificate() :: essh_pkt:essh_certificate().

-export_type([essh_agent/0, essh_constraint/0]).


-spec request_identities(essh_agent()) ->
	  {ok, [{essh_public_key() | essh_certificate(), Comment :: binary()}]} |
	  {error, Reason :: term()}.
request_identities(Agent) ->
    Req = <<?BYTE(?SSH_AGENTC_REQUEST_IDENTITIES)>>,
    request_identities1(req(Agent, Req)).

request_identities1({error, _} = E) -> E;
request_identities1({ok, <<?BYTE(?SSH_AGENT_IDENTITIES_ANSWER),
			   ?UINT32(Count), Data/binary >>}) ->
    request_identities2(Count, Data, []).

request_identities2(0, <<>>, Acc) ->
    {ok, lists:filtermap(fun request_identities3/1, Acc)};
request_identities2(N, <<?BINARY(KeyBlob, _KeyBlobLen),
			 ?BINARY(Comment, _CommentLen),
			 Rest/binary>>, Acc) ->
    request_identities2(N - 1, Rest, [{KeyBlob, Comment}|Acc]);
request_identities2(_,_,_) -> {error, unexpected_data}.

request_identities3({K, C}) ->
    try {true, {essh_pkt:dec_signature_key(K), C}}
    catch error:function_clause ->
	    request_identities4({K, C})
    end.

request_identities4({K, C}) ->
    try {true, {essh_pkt:dec_cert(K), C}}
    catch error:function_clause ->
	    false
    end.


-spec sign_request(essh_agent(), TBS :: binary(), essh_public_key()) ->
	  {ok, Signature :: binary()} | {error, Reason :: term()}.
sign_request(Agent, TBS, SignatureKey) ->
    KeyBlob = essh_pkt:enc_signature_key(SignatureKey),
    Flags = ?SSH_AGENT_RSA_SHA2_512 + ?SSH_AGENT_RSA_SHA2_256,
    Req = <<?BYTE(?SSH_AGENTC_SIGN_REQUEST),
	    ?BINARY(KeyBlob), ?BINARY(TBS), ?UINT32(Flags)>>,
    sign_request1(req(Agent, Req)).

sign_request1({error, _} = E) ->
    E;
sign_request1({ok, <<?BYTE(?SSH_AGENT_FAILURE)>>}) -> {error, agent_failure};
sign_request1({ok, <<?BYTE(?SSH_AGENT_SIGN_RESPONSE),
		     ?BINARY(Signature, SingatureLen)>>}) ->
    {ok, Signature}.


-spec add_identity(essh_agent(), essh_private_key(), essh_certificate(),
		   Comment :: binary()) ->
	  ok | {error, Reason :: term()}.
add_identity(Agent, PrivateKey, #{type_info := TypeInfo} = Cert, Comment) ->
    CertBlob = essh_pkt:enc_cert(Cert),
    Req = <<?BYTE(?SSH_AGENTC_ADD_IDENTITY),
	    ?BINARY(TypeInfo), ?BINARY(CertBlob),
	    (essh_pkt:enc_private_key_cert(PrivateKey))/binary,
	    ?BINARY(Comment)>>,
    simple_req(Agent, Req).

-spec add_identity(essh_agent(), essh_private_key(), Comment :: binary()) ->
	  ok | {error, Reason :: term()}.
add_identity(Agent, PrivateKey, Comment) ->
    Req = <<?BYTE(?SSH_AGENTC_ADD_IDENTITY),
	    (essh_pkt:enc_private_key(PrivateKey))/binary,
	    ?BINARY(Comment)>>,
    simple_req(Agent, Req).


-spec remove_identity(essh_agent(), essh_public_key()) ->
	  ok | {error, Reason :: term()}.
remove_identity(Agent, PublicKey) ->
    KeyBlob = essh_pkt:enc_signature_key(PublicKey),
    Req = <<?BYTE(?SSH_AGENTC_REMOVE_IDENTITY), ?BINARY(KeyBlob)>>,
    simple_req(Agent, Req).


-spec remove_all_identities(essh_agent()) -> ok | {error, Reason :: term()}.
remove_all_identities(Agent) ->
    simple_req(Agent, <<?BYTE(?SSH_AGENTC_REMOVE_ALL_IDENTITIES)>>).


-spec add_id_constrained(essh_agent(), essh_private_key(), essh_certificate(),
			 Comment :: binary(), [essh_constraint()]) ->
	  ok | {error, Reason :: term()}.
add_id_constrained(Agent, PrivateKey, #{type_info := TypeInfo} = Cert, Comment,
		   Constraints) ->
    CertBlob = essh_pkt:enc_cert(Cert),
    Req = <<?BYTE(?SSH_AGENTC_ADD_IDENTITY),
	    ?BINARY(TypeInfo), ?BINARY(CertBlob),
	    (essh_pkt:enc_private_key_cert(PrivateKey))/binary,
	    ?BINARY(Comment),
	    (essh_pkt:enc_constraints(Constraints))/binary>>,
    simple_req(Agent, Req).


-spec add_id_constrained(essh_agent(), essh_private_key(),
			 Comment :: binary(), [essh_constraint()]) ->
	  ok | {error, Reason :: term()}.
add_id_constrained(Agent, PrivateKey, Comment, Constraints) ->
    Req = <<?BYTE(?SSH_AGENTC_ADD_IDENTITY),
	    (essh_pkt:enc_private_key(PrivateKey))/binary,
	    ?BINARY(Comment),
	    (essh_pkt:enc_constraints(Constraints))/binary>>,
    simple_req(Agent, Req).


-spec add_smartcard_key(essh_agent(), Id :: binary(), Pin :: binary()) ->
	  ok | {error, Reason :: term()}.
add_smartcard_key(Agent, Id, Pin) ->
    Req = <<?BYTE(?SSH_AGENTC_ADD_SMARTCARD_KEY),
	    ?BINARY(Id), ?BINARY(Pin)>>,
    simple_req(Agent, Req).


-spec remove_smartcard_key(essh_agent(), Id :: binary()) ->
	  ok | {error, Reason :: term()}.
remove_smartcard_key(Agent, Id) when is_binary(Id) ->
    Req = <<?BYTE(?SSH_AGENTC_REMOVE_SMARTCARD_KEY), ?BINARY(Id)>>,
    simple_req(Agent, Req).


-spec remove_smartcard_key(essh_agent(),Id :: binary(), Pin :: binary()) ->
	  ok | {error, Reason :: term()}.
remove_smartcard_key(Agent, Id, Pin)
  when is_binary(Id), is_binary(Pin) ->
    Req = <<?BYTE(?SSH_AGENTC_REMOVE_SMARTCARD_KEY),
	    ?BINARY(Id), ?BINARY(Pin)>>,
    simple_req(Agent, Req).


-spec lock(essh_agent(), Password :: binary()) ->
	  ok | {error, Reason :: term()}.
lock(Agent, Password) when is_binary(Password) ->
    Req = <<?BYTE(?SSH_AGENTC_LOCK), ?BINARY(Password)>>,
    simple_req(Agent, Req).


-spec unlock(essh_agent(), Password :: binary()) ->
	  ok | {error, Reason :: term()}.
unlock(Agent, Password) when is_binary(Password) ->
    Req = <<?BYTE(?SSH_AGENTC_UNLOCK), ?BINARY(Password)>>,
    simple_req(Agent, Req).


-spec add_smartcard_key_constrained(essh_agent(), Id :: binary(),
				    Pin :: binary(), [essh_constraint()]) ->
	  ok | {error, Reason :: term()}.
add_smartcard_key_constrained(Agent, Id, Pin, Constraints)
  when is_binary(Id), is_binary(Pin) ->
    Req = <<?BYTE(?SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED),
	    ?BINARY(Id), ?BINARY(Pin),
	    (essh_pkt:enc_constraints(Constraints))/binary>>,
    simple_req(Agent, Req).



-spec simple_req(essh_agent(), Request :: binary()) ->
	  ok | {error, Reason :: term()}.
simple_req(Agent, Req) -> simple_req1(req(Agent, Req)).

simple_req1({error, _} = E) -> E;
simple_req1({ok, <<?BYTE(?SSH_AGENT_FAILURE)>>}) -> {error, agent_failure};
simple_req1({ok, <<?BYTE(?SSH_AGENT_SUCCESS)>>}) -> ok;
simple_req1({ok, _}) -> {error, unexpected_data}.


-spec req(essh_agent(), Request :: binary()) ->
	  {ok, Response :: binary()} | {error, Reason :: term()}.
req({local, _} = AuthSock, Req) when is_binary(Req) ->
    local_req(AuthSock, Req);
req({remote, Connection}, Req) when is_binary(Req), is_pid(Connection) ->
    remote_req(Connection, Req).


local_req(AuthSock, Req) ->
    Opts = [{active, false}, binary, {packet, 4}],
    local_req1(gen_tcp:connect(AuthSock, 0, Opts), Req).

local_req1({error, _} = E, _) -> E;
local_req1({ok, Sock}, Req) -> local_req2(gen_tcp:send(Sock, Req) ,Sock).

local_req2({error, _} = E, Sock) -> _ = gen_tcp:close(Sock), E;
local_req2(ok, Sock) ->
    Resp = gen_tcp:recv(Sock, 0),
    _ = gen_tcp:close(Sock),
    Resp.


-define(TIMEOUT, 1000).
remote_req(Connection, Req) ->
    Self = self(),
    Pid = spawn( fun() -> Self ! {remote_req, remote_req1(Connection, Req)} end),
    receive {remote_req, R} -> R
    after 2000 ->
	    exit(Pid,kill),
	    {error, timeout}
    end.


remote_req1(Connection, Req) ->
    MaybeChannel =
	ssh_connection:open_channel(Connection, "auth-agent@openssh.com", <<>>, ?TIMEOUT),
    remote_req2(MaybeChannel, Connection, Req).

remote_req2({ok, Channel}, Connection, Req) ->
    MaybeOk = ssh_connection:send(Connection, Channel, 0, <<?BINARY(Req)>>),
    remote_req3(MaybeOk, Channel, Connection);
remote_req2(E, _, _) -> {error, E}.


remote_req3({error, _} = E, Channel, Connection) ->
    _ = ssh_connection:close(Connection, Channel), E;
remote_req3(ok, Channel, Connection)  ->
    R = receive
	    {ssh_cm, Connection, {data, Channel, 0, <<?BINARY(Data, _DataLen)>>}} ->
		{ok, Data};
	    Unexpected -> {error, {unexpected, Unexpected}}
	after ?TIMEOUT -> {error, timeout} end,
    _ = ssh_connection:close(Connection, Channel),
    R.
