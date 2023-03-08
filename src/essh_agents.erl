-module(essh_agents).

-behaviour(gen_statem).

-export([init/1, handle_event/4, callback_mode/0]).

-export([start_link/1, start_link/0]).
-export([req/2]).

-include("essh_binary.hrl").
-include("essh_agent_constants.hrl").

-include_lib("stdlib/include/ms_transform.hrl").

-type essh_certificate() :: essh_pkt:essh_certificate().
-type essh_public_key() :: essh_pkt:essh_public_key().
-type essh_private_key() :: essh_pkt:essh_private_key().

-record(t, {
    pubOrCert :: essh_public_key() | essh_certificate(),
    priv :: essh_private_key(),
    comment :: binary(),
    confirm :: boolean(),
    expire :: non_neg_integer() | undefined
}).

start_link() -> start_link([]).

-spec start_link([{confirm, function()}]) -> 'ignore' | {'error', _} | {'ok', pid()}.
start_link(Opts) when is_list(Opts) ->
    gen_statem:start_link(?MODULE, Opts, []).

init(Opts) ->
    Confirm =
        case proplists:get_value(confirm, Opts, undefined) of
            F when is_function(F) -> F;
            _ -> fun(_) -> true end
        end,
    Tab = ets:new(?MODULE, [{keypos, #t.pubOrCert}, private]),
    {ok, unlocked, #{tab => Tab, confirm_fun => Confirm}}.

callback_mode() -> handle_event_function.

-spec req(pid(), binary()) -> binary().
req(Pid, Req) when is_pid(Pid), is_binary(Req) ->
    try
        req1(Pid, Req)
    catch
        _:_ -> <<?BYTE(?SSH_AGENT_FAILURE)>>
    end.

req1(Pid, <<?BYTE(?SSH_AGENTC_REQUEST_IDENTITIES)>>) ->
    {ok, Ids} = gen_statem:call(Pid, list),
    <<?BYTE(?SSH_AGENT_IDENTITIES_ANSWER), (essh_pkt:enc_identities_answer(Ids))/binary>>;
req1(Pid, <<
    ?BYTE(?SSH_AGENTC_SIGN_REQUEST),
    ?BINARY(PubOrCertBlob, _PubOrCertBlobLen),
    ?BINARY(TBS, _TBSLen),
    ?UINT32(_Flags)
>>) ->
    PubOrCert = essh_pkt:dec_key_or_cert(PubOrCertBlob),
    {ok, {SignInfo, Signature}} =
        gen_statem:call(Pid, {sign, PubOrCert, TBS}),
    SignatureBlob = <<?BINARY(SignInfo), ?BINARY(Signature)>>,
    <<?BYTE(?SSH_AGENT_SIGN_RESPONSE), ?BINARY(SignatureBlob)>>;
req1(Pid, <<?BYTE(?SSH_AGENTC_ADD_IDENTITY), Req/binary>>) ->
    {PubOrCert, Priv, Comment, []} = essh_pkt:dec_add_id(Req),
    req2(
        gen_statem:call(
            Pid,
            {add, #t{
                pubOrCert = PubOrCert,
                priv = Priv,
                comment = Comment,
                confirm = false,
                expire = undefined
            }}
        )
    );
req1(Pid, <<?BYTE(?SSH_AGENTC_REMOVE_IDENTITY), ?BINARY(PubOrCertBlob, _PubOrCertBlobLen)>>) ->
    PubOrCert = essh_pkt:dec_key_or_cert(PubOrCertBlob),
    req2(gen_statem:call(Pid, {remove, PubOrCert}));
req1(Pid, <<?BYTE(?SSH_AGENTC_REMOVE_ALL_IDENTITIES)>>) ->
    req2(gen_statem:call(Pid, remove_all));
req1(Pid, <<?BYTE(?SSH_AGENTC_ADD_ID_CONSTRAINED), Req/binary>>) ->
    {PubOrCert, Priv, Comment, Constraints} = essh_pkt:dec_add_id(Req),
    Confirm = proplists:get_bool(confirm, Constraints),
    Expire =
        case proplists:get_value(lifetime, Constraints) of
            N when is_integer(N) -> now_seconds() + N;
            _ -> undefined
        end,
    req2(
        gen_statem:call(
            Pid,
            {add, #t{
                pubOrCert = PubOrCert,
                priv = Priv,
                comment = Comment,
                confirm = Confirm,
                expire = Expire
            }}
        )
    );
req1(Pid, <<?BYTE(?SSH_AGENTC_LOCK), ?BINARY(Password, _PasswordLen)>>) ->
    req2(gen_statem:call(Pid, {lock, Password}));
req1(Pid, <<?BYTE(?SSH_AGENTC_UNLOCK), ?BINARY(Password, _PasswordLen)>>) ->
    req2(gen_statem:call(Pid, {unlock, Password})).

req2(ok) -> <<?BYTE(?SSH_AGENT_SUCCESS)>>;
req2(_) -> <<?BYTE(?SSH_AGENT_FAILURE)>>.

handle_event({call, From}, list, locked, _) ->
    {keep_state_and_data, [{reply, From, {ok, []}}]};
handle_event({call, From}, list, unlocked, #{tab := Tab}) ->
    expire(Tab),
    L = [{Id, C} || #t{pubOrCert = Id, comment = C} <- ets:tab2list(Tab)],
    {keep_state_and_data, [{reply, From, {ok, L}}]};
handle_event({call, From}, {add, Id}, unlocked, #{tab := Tab}) ->
    ets:insert(Tab, Id),
    {keep_state_and_data, [{reply, From, ok}]};
handle_event(
    {call, From},
    {sign, PubOrCert, TBS},
    unlocked,
    #{tab := Tab, confirm_fun := ConfirmFun}
) ->
    expire(Tab),
    R = do_sign(ets:lookup(Tab, PubOrCert), TBS, ConfirmFun),
    {keep_state_and_data, [{reply, From, R}]};
handle_event({call, From}, {remove, PubOrCert}, unlocked, #{tab := Tab}) ->
    expire(Tab),
    R =
        case ets:lookup(Tab, PubOrCert) of
            [] ->
                {error, no_matching_key};
            _ ->
                ets:delete(Tab, PubOrCert),
                ok
        end,
    {keep_state_and_data, [{reply, From, R}]};
handle_event({call, From}, remove_all, unlocked, #{tab := Tab}) ->
    ets:delete_all_objects(Tab),
    {keep_state_and_data, [{reply, From, ok}]};
handle_event({call, From}, {lock, Password}, unlocked, D) ->
    {next_state, locked, {Password, D}, [{reply, From, ok}]};
handle_event({call, From}, {unlock, Password}, locked, {Password, D}) ->
    {next_state, unlocked, D, [{reply, From, ok}]};
handle_event({call, From}, _, _, _) ->
    {keep_state_and_data, [{reply, From, {error, agent_failure}}]}.

-spec now_seconds() -> non_neg_integer().
now_seconds() -> calendar:datetime_to_gregorian_seconds({date(), time()}).

expire(Tab) ->
    NowSeconds = now_seconds(),
    MS = ets:fun2ms(
        fun
            (#t{expire = Exp}) when is_integer(Exp), Exp < NowSeconds -> true;
            (_) -> false
        end
    ),
    ets:select_delete(Tab, MS).

signinfo_digetstype(#{public_key := Pub}) ->
    signinfo_digetstype(Pub);
signinfo_digetstype(Pub) ->
    SignInfo = essh_cert:signinfo(Pub),
    DigestType = essh_cert:digest_type(SignInfo),
    {SignInfo, DigestType}.

do_sign([], _, _) ->
    {error, no_matching_key};
do_sign(
    [#t{pubOrCert = PubOrCert, confirm = true, comment = Comment} = Id],
    TBS,
    ConfirmFun
) ->
    case ConfirmFun({PubOrCert, Comment}) of
        true -> do_sign1(Id, TBS);
        false -> {error, not_confirmed}
    end;
do_sign([#t{confirm = false} = Id], TBS, _) ->
    do_sign1(Id, TBS).

do_sign1(#t{pubOrCert = PubOrCert, priv = Priv}, TBS) ->
    {SignInfo, DigestType} = signinfo_digetstype(PubOrCert),
    {ok, {SignInfo, essh_cert:key_sign1(TBS, DigestType, Priv)}}.
