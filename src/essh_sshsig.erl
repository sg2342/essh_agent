-module(essh_sshsig).

-export([armor/1, unarmor/1]).

-export([key_sign/3, agent_sign/4, verify/2]).

-include("essh_binary.hrl").

-define(ARMOR_LINE_LEN, 70).
-define(ARMOR_HEADER, <<"-----BEGIN SSH SIGNATURE-----">>).
-define(ARMOR_FOOTER, <<"-----END SSH SIGNATURE-----">>).

-spec armor(binary()) -> binary().
armor(InBin) ->
    Bin = base64:encode(InBin),
    F = fun
        F(B, Acc) when byte_size(B) < ?ARMOR_LINE_LEN ->
            [?ARMOR_HEADER | lists:reverse([?ARMOR_FOOTER, B | Acc])];
        F(<<B:?ARMOR_LINE_LEN/binary, R/binary>>, Acc) ->
            F(R, [B | Acc])
    end,
    iolist_to_binary([<<B/binary, "\n">> || B <- F(Bin, [])]).

-spec unarmor(binary()) -> binary().
unarmor(Bin) ->
    L = binary:split(Bin, [<<"\n">>, <<"\r\n">>], [global, trim]),
    ?ARMOR_HEADER = hd(L),
    ?ARMOR_FOOTER = lists:last(L),
    base64:mime_decode(iolist_to_binary(lists:sublist(L, 2, length(L) - 2))).

-define(MAGIC_PREAMBLE, "SSHSIG").

-spec key_sign(
    public_key:private_key(),
    Namespace :: binary(),
    Message :: binary() | {sha256 | sha512, H :: binary()}
) ->
    SshSig :: binary().
key_sign(Key, Namespace, Message) when is_binary(Message) ->
    key_sign(Key, Namespace, {sha512, crypto:hash(sha512, Message)});
key_sign(Key, Namespace, {HashAlgo, H}) when HashAlgo == sha256; HashAlgo == sha512 ->
    TBS =
        <<?MAGIC_PREAMBLE, ?BINARY(Namespace), ?BINARY(<<>>), ?BINARY((hash_algorithm(HashAlgo))),
            ?BINARY(H)>>,
    PublicKey = essh_pkt:pubkey(Key),
    SignInfo = essh_cert:signinfo(PublicKey),
    Signature = essh_cert:key_sign1(TBS, essh_cert:digest_type(SignInfo), Key),
    SignatureBlob = <<?BINARY(SignInfo), ?BINARY(Signature)>>,
    <<?MAGIC_PREAMBLE, ?UINT32(1), ?BINARY((essh_pkt:enc_signature_key(PublicKey))),
        ?BINARY(Namespace), ?BINARY(<<>>), ?BINARY((hash_algorithm(HashAlgo))),
        ?BINARY(SignatureBlob)>>.

-spec agent_sign(
    public_key:public_key(),
    essh_agentc:essh_agent(),
    Namespace :: binary(),
    Message :: binary() | {sha256 | sha512, H :: binary()}
) -> {ok, SshSig :: binary()} | {error, Reason :: term()}.
agent_sign(SignatureKey, Agent, Namespace, Message) when is_binary(Message) ->
    agent_sign(SignatureKey, Agent, Namespace, {sha512, crypto:hash(sha512, Message)});
agent_sign(SignatureKey, Agent, Namespace, {HashAlgo, H}) ->
    TBS =
        <<?MAGIC_PREAMBLE, ?BINARY(Namespace), ?BINARY(<<>>), ?BINARY((hash_algorithm(HashAlgo))),
            ?BINARY(H)>>,
    Pkt =
        <<?MAGIC_PREAMBLE, ?UINT32(1), ?BINARY((essh_pkt:enc_signature_key(SignatureKey))),
            ?BINARY(Namespace), ?BINARY(<<>>), ?BINARY((hash_algorithm(HashAlgo)))>>,
    agent_sign1(essh_agentc:sign_request(Agent, TBS, SignatureKey), Pkt).

agent_sign1({ok, SignatureBlob}, Pkt) -> {ok, <<Pkt/binary, ?BINARY(SignatureBlob)>>};
agent_sign1({error, _} = E, _) -> E.

-spec verify(SshSig :: binary(), Message :: binary() | {sha256 | sha512, H :: binary()}) ->
    false | {public_key:public_key(), Namespace :: binary()}.
verify(SshSig, MessageOrDigest) ->
    verify1(decode(SshSig), MessageOrDigest).

verify1(#{hash_algorithm := HashAlgo} = M, Message) when is_binary(Message) ->
    verify1(M, {HashAlgo, crypto:hash(HashAlgo, Message)});
verify1(
    #{
        version := 1,
        public_key := PublicKey,
        namespace := Namespace,
        hash_algorithm := HashAlgo,
        signature := {SignInfo, Signature}
    },
    {HashAlgo, H}
) ->
    TBS =
        <<?MAGIC_PREAMBLE, ?BINARY(Namespace), ?BINARY(<<>>), ?BINARY((hash_algorithm(HashAlgo))),
            ?BINARY(H)>>,
    essh_cert:verify1(TBS, essh_cert:digest_type(SignInfo), Signature, PublicKey) andalso
        {PublicKey, Namespace}.

decode(
    <<?MAGIC_PREAMBLE, ?UINT32(Version), ?BINARY(PublicKey, _PublicKeyLen),
        ?BINARY(Namespace, _NamespaceLen), ?BINARY(Reserved, _ReservedLen),
        ?BINARY(HashAlgo, _HashAlgo), ?BINARY(SignatureBlob, _SignatureBlobLen)>>
) ->
    <<?BINARY(SignInfo, SignInfoLen), ?BINARY(Signature, SignatureLen)>> = SignatureBlob,
    #{
        version => Version,
        public_key => essh_pkt:dec_signature_key(PublicKey),
        namespace => Namespace,
        reserved => Reserved,
        hash_algorithm => hash_algorithm(HashAlgo),
        signature => {SignInfo, Signature}
    }.

hash_algorithm(<<"sha256">>) -> sha256;
hash_algorithm(<<"sha512">>) -> sha512;
hash_algorithm(sha256) -> <<"sha256">>;
hash_algorithm(sha512) -> <<"sha512">>.
