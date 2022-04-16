-module(essh_agentc).

-export([request_identities/1,
	 sign_request/3,
	 add_identity/3,
	 remove_identity/2,
	 remove_all_identities/1,
	 add_id_constrained/4,
	 add_smartcard_key/3,
	 remove_smartcard_key/2,
	 remove_smartcard_key/3,
	 lock/2,
	 unlock/2,
	 add_smartcard_key_constrained/4] ).

-include("essh_agent_constants.hrl").

-type essh_agent() :: {local, SshAuthSock :: file:name_all()}.
-type essh_constraint() :: confirm | {lifetime, Seconds :: pos_integer()} |
			   Extension :: {Name :: binary(), Value :: binary()}.

-type essh_public_key() :: public_key:rsa_public_key() |
			   public_key:dsa_public_key() |
			   public_key:ec_public_key() |
			   public_key:ed_public_key().

-type essh_private_key() :: public_key:rsa_private_key() |
			    public_key:dsa_private_key() |
			    public_key:ec_private_key() |
			    public_key:ed_private_key().


-spec request_identities(essh_agent()) ->
	  {ok, [{essh_public_key(), Comment :: binary()}]} | {error, Reason :: term()}.
request_identities(Agent) ->
    Req = <<?SSH_AGENTC_REQUEST_IDENTITIES>>,
    request_identities1(req(Agent, Req)).

request_identities1({error, _} = E) -> E;
request_identities1({ok, <<?SSH_AGENT_IDENTITIES_ANSWER,
			   Count:32, Data/binary >>}) -> 
    request_identities2(Count, Data, []).

request_identities2(0, <<>>, Acc) ->
    {ok, lists:filtermap(fun request_identities3/1, Acc)};
request_identities2(N, <<KbL:32, KeyBlob:KbL/binary,
			 CL:32, Comment:CL/binary,
			 Rest/binary>>, Acc) ->
    request_identities2(N - 1, Rest, [{KeyBlob, Comment}|Acc]);
request_identities2(_,_,_) -> {error, unexpected_data}.

request_identities3({K, C}) ->
    try {true, {essh_pkt:dec_signature_key(K), C}}
    catch error:function_clause -> false end.


-spec sign_request(essh_agent(), TBS :: binary(), essh_public_key()) ->
	  {ok, Signature :: binary()} | {error, Reason :: term()}.
sign_request(Agent, TBS, SignatureKey) ->
    KeyBlob = essh_pkt:enc_signature_key(SignatureKey),
    Flags = ?SSH_AGENT_RSA_SHA2_512 + ?SSH_AGENT_RSA_SHA2_256,
    Req = <<?SSH_AGENTC_SIGN_REQUEST,
	    (size(KeyBlob)):32, KeyBlob/binary,
	    (size(TBS)):32, TBS/binary,
	    Flags:32>>,
    sign_request1(req(Agent, Req)).

sign_request1({error, _} = E) ->
    E;
sign_request1({ok, <<?SSH_AGENT_FAILURE>>}) -> {error, agent_failure};
sign_request1({ok, <<?SSH_AGENT_SIGN_RESPONSE,
		     SgnL:32, Signature:SgnL/binary>>}) ->
    {ok, Signature}.


-spec add_identity(essh_agent(), essh_private_key(), Comment :: binary()) ->
	  ok | {error, Reason :: term()}.
add_identity(Agent, PrivateKey, Comment) ->
    Req = <<?SSH_AGENTC_ADD_IDENTITY,
	    (essh_pkt:enc_private_key(PrivateKey))/binary,
	    (size(Comment)):32, Comment/binary>>,
    simple_req(Agent, Req).


-spec remove_identity(essh_agent(), essh_public_key()) ->
	  ok | {error, Reason :: term()}.
remove_identity(Agent, PublicKey) ->
    KeyBlob = essh_pkt:enc_signature_key(PublicKey),
    Req = <<?SSH_AGENTC_REMOVE_IDENTITY,
	    (size(KeyBlob)):32, KeyBlob/binary>>,
    simple_req(Agent, Req).


-spec remove_all_identities(essh_agent()) ->
	  ok | {error, Reason :: term()}.
remove_all_identities(Agent) ->
    simple_req(Agent, <<?SSH_AGENTC_REMOVE_ALL_IDENTITIES>>).


-spec add_id_constrained(essh_agent(), essh_private_key(),
			 Comment :: binary(), [essh_constraint()]) ->
	  ok | {error, Reason :: term()}.
add_id_constrained(Agent, PrivateKey, Comment, Constraints) ->
    Cns = list_to_binary(lists:map(fun enc_constraint/1, Constraints)),
    Req = <<?SSH_AGENTC_ADD_IDENTITY,
	    (essh_pkt:enc_private_key(PrivateKey))/binary,
	    (size(Comment)):32, Comment/binary,
	    Cns/binary>>,
    simple_req(Agent, Req).


-spec add_smartcard_key(essh_agent(), Id :: binary(), Pin :: binary()) ->
	  ok | {error, Reason :: term()}.
add_smartcard_key(Agent, Id, Pin) ->
    Req = <<?SSH_AGENTC_ADD_SMARTCARD_KEY,
	    (size(Id)):32, Id/binary,
	    (size(Pin)):32, Pin/binary >>,
    simple_req(Agent, Req).


-spec remove_smartcard_key(essh_agent(), Id :: binary()) ->
	  ok | {error, Reason :: term()}.
remove_smartcard_key(Agent, Id) when is_binary(Id) ->
    Req = <<?SSH_AGENTC_REMOVE_SMARTCARD_KEY,
	    (size(Id)):32, Id/binary >>,
    simple_req(Agent, Req).


-spec remove_smartcard_key(essh_agent(),Id :: binary(), Pin :: binary()) ->
	  ok | {error, Reason :: term()}.
remove_smartcard_key(Agent, Id, Pin)
  when is_binary(Id), is_binary(Pin) ->
    Req = << ?SSH_AGENTC_REMOVE_SMARTCARD_KEY,
	     (size(Id)):32, Id/binary,
	     (size(Pin)):32, Pin/binary >>,
    simple_req(Agent, Req).


-spec lock(essh_agent(), Password :: binary()) ->
	  ok | {error, Reason :: term()}.
lock(Agent, Password) when is_binary(Password) ->
    Req = <<?SSH_AGENTC_LOCK, (size(Password)):32, Password/binary>>,
    simple_req(Agent, Req).


-spec unlock(essh_agent(), Password :: binary()) ->
	  ok | {error, Reason :: term()}.
unlock(Agent, Password) when is_binary(Password) ->
    Req = <<?SSH_AGENTC_UNLOCK, (size(Password)):32, Password/binary>>,
    simple_req(Agent, Req).


-spec add_smartcard_key_constrained(essh_agent(), Id :: binary(),
				    Pin :: binary(), [essh_constraint()]) ->
	  ok | {error, Reason :: term()}.
add_smartcard_key_constrained(Agent, Id, Pin, Constraints)
  when is_binary(Id), is_binary(Pin) ->
    Cns = list_to_binary(lists:map(fun enc_constraint/1, Constraints)),
    Req = << ?SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED,
	     (size(Id)):32, Id/binary,
	     (size(Pin)):32, Pin/binary,
	     Cns/binary >>,
    simple_req(Agent, Req).


-spec enc_constraint(essh_constraint()) -> binary().
enc_constraint(confirm) ->
    << ?SSH_AGENT_CONSTRAIN_CONFIRM >>;
enc_constraint({lifetime, Seconds}) when is_integer(Seconds), Seconds > 0 ->
    << ?SSH_AGENT_CONSTRAIN_LIFETIME, Seconds:32 >>;
enc_constraint({Name, Value}) when is_binary(Name), is_binary(Value) ->
    << ?SSH_AGENT_CONSTRAIN_EXTENSION
     , (size(Name)):32, Name/binary
     , Value/binary >>.


-spec simple_req(essh_agent(), Request :: binary()) ->
	  ok | {error, Reason :: term()}.
simple_req(Agent, Req) -> simple_req1(req(Agent, Req)).

simple_req1({error, _} = E) ->
    E;
simple_req1({ok, <<?SSH_AGENT_FAILURE>>}) -> {error, agent_failure};
simple_req1({ok, <<?SSH_AGENT_SUCCESS>>}) -> ok;
simple_req1({ok, _}) -> {error, unexpected_data}.


-spec req(essh_agent(), Request :: binary()) ->
	  {ok, Response :: binary()} | {error, Reason :: term()}.
req({local, _} = AuthSock, Req) when is_binary(Req) -> local_req(AuthSock, Req).


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
