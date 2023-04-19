-module(essh_cert).

-export([key_sign/2, agent_sign/3, verify/1]).
-export([signinfo/1, key_sign1/3, digest_type/1]).

-include_lib("public_key/include/public_key.hrl").

-include("essh_binary.hrl").

-type essh_sign_request() ::
    #{
        public_key := public_key:public_key(),
        serial := 0..18446744073709551615,
        cert_type := host | user,
        key_id := binary(),
        valid_principals := [binary()],
        valid_before := 0..18446744073709551615,
        valid_after := 0..18446744073709551615,
        critical_options := [{binary(), binary()}],
        extensions := [{binary(), binary()}]
    }.

-export_type([essh_sign_request/0]).

-spec verify(essh_pkt:essh_certificate()) -> boolean().
verify(#{signature_key := Key, signature := {SigInfo, Sig}} = Cert) ->
    TBS = essh_pkt:enc_tbs(Cert),
    DigestType = digest_type(SigInfo),
    verify1(TBS, DigestType, Sig, Key).

verify1(
    TBS,
    DigestType,
    <<?MPINT(R, _RLen), ?MPINT(S, _SLen)>>,
    {#'ECPoint'{}, _} = Key
) ->
    DER = public_key:der_encode(
        'ECDSA-Sig-Value',
        #'ECDSA-Sig-Value'{r = R, s = S}
    ),
    public_key:verify(TBS, DigestType, DER, Key);
verify1(
    TBS,
    DigestType,
    <<R:160/big-unsigned-integer, S:160/big-unsigned-integer>>,
    {_, #'Dss-Parms'{}} = Key
) ->
    DER = public_key:der_encode(
        'Dss-Sig-Value',
        #'Dss-Sig-Value'{r = R, s = S}
    ),
    public_key:verify(TBS, DigestType, DER, Key);
verify1(TBS, DigestType, Signature, Key) ->
    public_key:verify(TBS, DigestType, Signature, Key).

-define(NONCE_LEN, 32).

-spec key_sign(essh_sign_request(), public_key:private_key()) -> essh_pkt:essh_certificate().
key_sign(#{public_key := PublicKey} = Request, Key) ->
    SignatureKey = essh_pkt:pubkey(Key),
    SignInfo = signinfo(SignatureKey),
    TypeInfo = <<(essh_pkt:key_type(PublicKey))/binary, "-cert-v01@openssh.com">>,
    Cert = Request#{
        type_info => TypeInfo,
        nonce => crypto:strong_rand_bytes(?NONCE_LEN),
        reserved => <<>>,
        signature_key => SignatureKey
    },
    TBS = essh_pkt:enc_tbs(Cert),
    Signature = key_sign1(TBS, digest_type(SignInfo), Key),
    Cert#{signature => {SignInfo, Signature}}.

-spec key_sign1(
    binary(),
    none | sha | sha256 | sha384 | sha512,
    public_key:private_key()
) -> binary().
key_sign1(TBS, DigestType, #'DSAPrivateKey'{} = Key) ->
    DER = public_key:sign(TBS, DigestType, Key),
    #'Dss-Sig-Value'{r = R, s = S} = public_key:der_decode('Dss-Sig-Value', DER),
    <<R:160/big-unsigned-integer, S:160/big-unsigned-integer>>;
key_sign1(TBS, DigestType, #'ECPrivateKey'{parameters = {'namedCurve', C}} = Key) when
    C == ?secp256r1; C == ?secp384r1; C == ?secp521r1
->
    DER = public_key:sign(TBS, DigestType, Key),
    #'ECDSA-Sig-Value'{r = R, s = S} = public_key:der_decode('ECDSA-Sig-Value', DER),
    <<(essh_pkt:mpint(R))/binary, (essh_pkt:mpint(S))/binary>>;
key_sign1(TBS, DigestType, Key) ->
    public_key:sign(TBS, DigestType, Key).

-spec agent_sign(essh_sign_request(), essh_agentc:essh_agent(), public_key:public_key()) ->
    {ok, essh_pkt:essh_certificate()} | {error, Reason :: term()}.
agent_sign(#{public_key := PublicKey} = Request, Agent, SignatureKey) ->
    TypeInfo = <<(essh_pkt:key_type(PublicKey))/binary, "-cert-v01@openssh.com">>,
    Cert = Request#{
        type_info => TypeInfo,
        nonce => crypto:strong_rand_bytes(?NONCE_LEN),
        reserved => <<>>,
        signature_key => SignatureKey
    },
    TBS = essh_pkt:enc_tbs(Cert),
    agent_sign1(essh_agentc:sign_request(Agent, TBS, SignatureKey), Cert).

agent_sign1({ok, <<?BINARY(I, _ILen), ?BINARY(S, _SLen)>>}, Cert) ->
    {ok, Cert#{signature => {I, S}}};
agent_sign1({error, _} = E, _) ->
    E.

-spec signinfo(public_key:public_key()) -> binary().
signinfo(#'RSAPublicKey'{}) ->
    <<"rsa-sha2-256">>;
signinfo({_, #'Dss-Parms'{}}) ->
    <<"ssh-dss">>;
signinfo({#'ECPoint'{}, {'namedCurve', ?'id-Ed25519'}}) ->
    <<"ssh-ed25519">>;
signinfo({#'ECPoint'{}, {'namedCurve', Oid}}) ->
    <<"ecdsa-sha2-", (essh_pkt:oid2curvename(Oid))/binary>>.

-spec digest_type(binary()) -> none | sha | sha256 | sha384 | sha512.
digest_type(<<"ecdsa-sha2-nistp256">>) -> sha256;
digest_type(<<"ecdsa-sha2-nistp384">>) -> sha384;
digest_type(<<"ecdsa-sha2-nistp521">>) -> sha512;
digest_type(<<"ssh-dss">>) -> sha;
digest_type(<<"ssh-ed25519">>) -> none;
digest_type(<<"rsa-sha2-512">>) -> sha512;
digest_type(<<"rsa-sha2-256">>) -> sha256;
digest_type(<<"ssh-rsa">>) -> sha.
