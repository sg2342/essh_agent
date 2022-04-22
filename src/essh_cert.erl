-module(essh_cert).

-export([sign/2, agent_sign/3, verify/1]).

-include_lib("public_key/include/public_key.hrl").

-include("essh_binary.hrl").

-type essh_certificate() :: essh_pkt:essh_certificate().
-type essh_private_key() :: essh_pkt:essh_private_key().
-type essh_public_key() :: essh_pkt:essh_public_key().

-type essh_agent() :: essh_agentc:essh_agent().

-type essh_sign_request() ::
 	#{ public_key := essh_public_key(),
	   serial := 0..18446744073709551615,
	   cert_type := host | user,
	   key_id := binary(),
	   valid_principals := [binary()],
	   valid_before := 0..18446744073709551615,
	   valid_after := 0..18446744073709551615,
	   critical_options := [{binary(), binary()}],
	   extensions := [{binary(), binary()}] }.


-spec verify(essh_certificate()) -> boolean().
verify(#{signature_key := Key, signature := {SigInfo, Sig}} = Cert) ->
    TBS = essh_pkt:enc_tbs(Cert),
    DigestType = essh_pkt:digest_type(SigInfo),
    verify1(TBS, DigestType, Sig, Key).

verify1(TBS, DigestType,
	<<?MPINT(R, _RLen), ?MPINT(S, _SLen)>>,
	{#'ECPoint'{},_} = Key) ->
    DER = public_key:der_encode('ECDSA-Sig-Value',
				#'ECDSA-Sig-Value'{r=R, s=S}),
    public_key:verify(TBS, DigestType, DER, Key);
verify1(TBS, DigestType,
	<<R:160/big-unsigned-integer, S:160/big-unsigned-integer>>,
	{_,  #'Dss-Parms'{}} = Key) ->
    DER = public_key:der_encode('Dss-Sig-Value',
				#'Dss-Sig-Value'{r = R, s = S}),
    public_key:verify(TBS, DigestType, DER, Key);
verify1(TBS, DigestType, Signature, Key) ->
    public_key:verify(TBS, DigestType, Signature, Key).


-define(NONCE_LEN,32).

-spec sign(essh_sign_request(), essh_private_key()) -> essh_certificate().
sign(#{public_key := PublicKey} = Request, Key) ->
    SignatureKey = pubkey(Key),
    SignInfo = signinfo(SignatureKey),
    TypeInfo = <<(essh_pkt:key_type(PublicKey))/binary, "-cert-v01@openssh.com">>,
    Cert = Request#{type_info => TypeInfo,
		    nonce => crypto:strong_rand_bytes(?NONCE_LEN),
		    reserved => <<>>,
		    signature_key => SignatureKey },
    TBS = essh_pkt:enc_tbs(Cert),
    Signature = key_sign(TBS, essh_pkt:digest_type(SignInfo), Key),
    Cert#{signature => {SignInfo, Signature}}.


key_sign(TBS, DigestType, #'DSAPrivateKey'{} = Key) ->
    DER = public_key:sign(TBS, DigestType, Key),
    #'Dss-Sig-Value'{r = R, s = S} = public_key:der_decode('Dss-Sig-Value', DER),
    <<R:160/big-unsigned-integer, S:160/big-unsigned-integer>>;
key_sign(TBS, DigestType, #'ECPrivateKey'{parameters = {namedCurve, C}} = Key)
  when C == ?secp256r1; C == ?secp384r1; C == ?secp521r1 ->
    DER = public_key:sign(TBS, DigestType, Key),
    #'ECDSA-Sig-Value'{r=R, s=S} = public_key:der_decode('ECDSA-Sig-Value', DER),
    << (essh_pkt:mpint(R))/binary, (essh_pkt:mpint(S))/binary>>;
key_sign(TBS, DigestType, Key) ->
    public_key:sign(TBS, DigestType, Key).


-spec agent_sign(essh_sign_request(), essh_agent(), essh_public_key()) ->
	  {ok, essh_certificate()} | {error, Reason :: term()}.
agent_sign(#{public_key := PublicKey} = Request, Agent, SignatureKey) ->
    TypeInfo = <<(essh_pkt:key_type(PublicKey))/binary, "-cert-v01@openssh.com">>,
    Cert = Request#{type_info => TypeInfo,
		    nonce => crypto:strong_rand_bytes(?NONCE_LEN),
		    reserved => <<>>,
		    signature_key => SignatureKey },
    TBS = essh_pkt:enc_tbs(Cert),
    case essh_agentc:sign_request(Agent, TBS, SignatureKey) of
	{ok, <<?BINARY(Info, _InfoLen), ?BINARY(Signature, _SignatureLen)>>} ->
	    {ok, Cert#{signature => {Info, Signature}}};
	{error, _} = E -> E
    end.


pubkey(#'RSAPrivateKey'{ publicExponent = E, modulus = N }) ->
    #'RSAPublicKey'{  publicExponent = E, modulus = N };
pubkey(#'DSAPrivateKey'{p = P, q = Q, g = G, y = Y}) ->
    {Y, #'Dss-Parms'{p = P, q = Q, g = G}};
pubkey(#'ECPrivateKey'{parameters = C, publicKey = Q}) ->
    {#'ECPoint'{point=Q}, C}.

signinfo(#'RSAPublicKey'{}) -> <<"rsa-sha2-256">>;
signinfo({_,#'Dss-Parms'{}}) -> <<"ssh-dss">>;
signinfo({#'ECPoint'{}, {namedCurve, ?'id-Ed25519'}}) -> <<"ssh-ed25519">>;
signinfo({#'ECPoint'{}, {namedCurve, Oid}}) ->
    <<"ecdsa-sha2-", (essh_pkt:oid2curvename(Oid))/binary>>.
