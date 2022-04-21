-module(essh_pkt).

-export([dec_signature_key/1,
	 enc_signature_key/1,
	 enc_private_key_cert/1,
	 enc_private_key/1]).

-export([enc_cert/1, dec_cert/1, digest_type/1, enc_tbs/1, key_type/1,
	 oid2curvename/1, mpint/1, dec_sig/1]).

-include_lib("public_key/include/public_key.hrl").

-type essh_public_key() :: public_key:rsa_public_key() |
			   public_key:dsa_public_key() |
			   public_key:ec_public_key() |
			   public_key:ed_public_key().

-type essh_private_key() :: public_key:rsa_private_key() |
			    public_key:dsa_private_key() |
			    public_key:ec_private_key() |
			    public_key:ed_private_key().

-type essh_certificate() ::
	#{ type_info := binary(),
	   nonce := binary(),
	   public_key := essh_public_key(),
	   serial := 0..18446744073709551615,
	   cert_type := host | user,
	   key_id := binary(),
	   valid_principals := [binary()],
	   valid_before := 0..18446744073709551615,
	   valid_after := 0..18446744073709551615,
	   critical_options := [{binary(), binary()}],
	   extensions := [{binary(), binary()}],
	   reserved := binary(),
	   signature_key := essh_public_key(),
	   signature := {binary(), binary()} }.

-export_type([essh_public_key/0, essh_private_key/0, essh_certificate/0]).


-spec enc_cert(essh_certificate()) -> binary().
enc_cert(#{type_info := TypeInfo,
	   nonce := Nonce,
	   public_key := PublicKey,
	   serial := Serial,
	   cert_type := CertType,
	   key_id := KeyId,
	   valid_principals := ValidPrincipals,
	   valid_before := ValidBefore,
	   valid_after := ValidAfter,
	   critical_options := CriticalOptions,
	   extensions := Extensions,
	   reserved := Reserved,
	   signature_key := SignatureKey,
	   signature := {SignInfo, Signature}}) ->
    list_to_binary([ enc_b(TypeInfo),
		     enc_b(Nonce), enc_pubkey(PublicKey),
		     << Serial:64 >>,
		     enc_cert_type(CertType),
		     enc_b(KeyId),
		     enc_b(lists:map(fun enc_b/1, ValidPrincipals)),
		     <<ValidAfter:64, ValidBefore:64>>,
		     enc_kvs(CriticalOptions),
		     enc_kvs(Extensions),
		     enc_b(Reserved),
		     enc_b(enc_signature_key(SignatureKey)),
		     enc_b([enc_b(SignInfo), enc_b(Signature)])
		   ]).


-spec dec_cert(binary()) -> essh_certificate().
dec_cert(<<TypeInfoLen:32, TypeInfo:TypeInfoLen/binary,
	   NonceLen:32, Nonce:NonceLen/binary,
	   PKLen:32, PK:PKLen/binary,
	   Rest/binary>>)
  when TypeInfo == <<"ssh-ed25519-cert-v01@openssh.com">> ->
    M = dec_cert_common(Rest),
    M#{type_info => TypeInfo,
       nonce => Nonce,
       public_key => {#'ECPoint'{point = PK}, {namedCurve, ?'id-Ed25519'}}};
dec_cert(<<TypeInfoLen:32, TypeInfo:TypeInfoLen/binary,
	   NonceLen:32, Nonce:NonceLen/binary,
	   ELen:32, E:ELen/big-signed-integer-unit:8,
	   NLen:32, N:NLen/big-signed-integer-unit:8,
	   Rest/binary>>)
  when TypeInfo == <<"ssh-rsa-cert-v01@openssh.com">>;
       TypeInfo == <<"rsa-sha2-256-cert-v01@openssh.com">>;
       TypeInfo == <<"rsa-sha2-512-cert-v01@openssh.com">> ->
    M = dec_cert_common(Rest),
    M#{type_info => TypeInfo,
       nonce => Nonce,
       public_key => #'RSAPublicKey'{modulus = N, publicExponent = E}};
dec_cert(<<TypeInfoLen:32, TypeInfo:TypeInfoLen/binary,
	   NonceLen:32, Nonce:NonceLen/binary,
	   PLen:32, P:PLen/big-signed-integer-unit:8,
	   QLen:32, Q:QLen/big-signed-integer-unit:8,
	   GLen:32, G:GLen/big-signed-integer-unit:8,
	   YLen:32, Y:YLen/big-signed-integer-unit:8,
	   Rest/binary>>)
  when TypeInfo == <<"ssh-dss-cert-v01@openssh.com">> ->
    M = dec_cert_common(Rest),
    M#{type_info => TypeInfo,
       nonce => Nonce,
       public_key => {Y, #'Dss-Parms'{p = P, q = Q, g = G}}};
dec_cert(<<TypeInfoLen:32, TypeInfo:TypeInfoLen/binary,
	   NonceLen:32, Nonce:NonceLen/binary,
	   CurveLen:32, Curve:CurveLen/binary,
	   PublicKeyLen:32, PublicKey:PublicKeyLen/binary,
	   Rest/binary>>)
  when TypeInfo == <<"ecdsa-sha2-nistp256-cert-v01@openssh.com">>;
       TypeInfo == <<"ecdsa-sha2-nistp384-cert-v01@openssh.com">>;
       TypeInfo == <<"ecdsa-sha2-nistp521-cert-v01@openssh.com">> ->
    M = dec_cert_common(Rest),
    M#{type_info => TypeInfo,
       nonce => Nonce,
       public_key => {#'ECPoint'{point = PublicKey},
		      {namedCurve, curvename2oid(Curve)}}}.

dec_cert_common(<<Serial:64,
                  CertType:32,
                  KeyIdLen:32, KeyId:KeyIdLen/binary,
                  ValidPrincipalsLen:32, ValidPrincipals:ValidPrincipalsLen/binary,
                  ValidAfter:64,
                  ValidBefore:64,
                  CriticalOptionsLen:32, CriticalOptions:CriticalOptionsLen/binary,
                  ExtensionsLen:32, Extensions:ExtensionsLen/binary,
                  ReservedLen:32, Reserved:ReservedLen/binary,
                  SignatureKeyLen:32, SignatureKey:SignatureKeyLen/binary,
                  SignatureLen:32, Signature:SignatureLen/binary>>) ->
    #{serial => Serial,
      cert_type => dec_cert_type(CertType),
      key_id => KeyId,
      valid_principals => dec_sl(ValidPrincipals, []),
      valid_before => ValidBefore,
      valid_after => ValidAfter,
      critical_options => dec_kvs(CriticalOptions, []),
      extensions => dec_kvs(Extensions, []),
      reserved => Reserved,
      signature_key => dec_signature_key(SignatureKey),
      signature => dec_sig(Signature)}.


-spec enc_tbs(essh_certificate()) -> binary().
enc_tbs(#{ type_info := TypeInfo,
	   nonce := Nonce,
	   public_key := PublicKey,
	   serial := Serial,
	   cert_type := CertType,
	   key_id := KeyId,
	   valid_principals := ValidPrincipals,
	   valid_before := ValidBefore,
	   valid_after := ValidAfter,
	   critical_options := CriticalOptions,
	   extensions := Extensions,
	   reserved := Reserved,
	   signature_key := SignatureKey }) ->
    list_to_binary([ enc_b(TypeInfo),
		     enc_b(Nonce),
		     enc_pubkey(PublicKey),
		     << Serial:64 >>,
		     enc_cert_type(CertType),
		     enc_b(KeyId),
		     enc_b(lists:map(fun enc_b/1, ValidPrincipals)),
		     <<ValidAfter:64, ValidBefore:64>>,
		     enc_kvs(CriticalOptions),
		     enc_kvs(Extensions),
		     enc_b(Reserved),
		     enc_b(enc_signature_key(SignatureKey))]).


-spec dec_signature_key(binary()) -> essh_public_key().
dec_signature_key(<<SigKInfoLen:32, SigKInfo:SigKInfoLen/binary,
		    ELen:32, E:ELen/big-signed-integer-unit:8,
		    NLen:32, N:NLen/big-signed-integer-unit:8 >>)
  when SigKInfo == <<"ssh-rsa">> ->
    #'RSAPublicKey'{ modulus = N, publicExponent = E};
dec_signature_key(<< SigKInfoLen:32, SigKInfo:SigKInfoLen/binary,
		     PLen:32, P:PLen/big-signed-integer-unit:8,
		     QLen:32, Q:QLen/big-signed-integer-unit:8,
		     GLen:32, G:GLen/big-signed-integer-unit:8,
		     YLen:32, Y:YLen/big-signed-integer-unit:8 >>)
  when SigKInfo == <<"ssh-dss">> ->
    {Y, #'Dss-Parms'{p = P, q = Q, g = G}};
dec_signature_key(<< SigKInfoLen:32, SigKInfo:SigKInfoLen/binary,
		     PKLen:32, PK:PKLen/binary >>)
  when SigKInfo == <<"ssh-ed25519">> ->
    { #'ECPoint'{ point = PK }, {namedCurve, ?'id-Ed25519'} };
dec_signature_key(<< SigKInfoLen:32, SigKInfo:SigKInfoLen/binary,
		     CurveLen:32, Curve:CurveLen/binary,
		     PKLen:32, PK:PKLen/binary >>)
  when SigKInfo == <<"ecdsa-sha2-nistp256">> ;
       SigKInfo == <<"ecdsa-sha2-nistp384">> ;
       SigKInfo == <<"ecdsa-sha2-nistp521">> ->
    {#'ECPoint'{ point = PK }, {namedCurve, curvename2oid(Curve)} }.


-spec enc_signature_key(essh_public_key()) -> binary().
enc_signature_key(SignatureKey) ->
    list_to_binary([ enc_b(key_type(SignatureKey))
		   , enc_pubkey(SignatureKey)]).

-spec enc_private_key_cert(essh_private_key()) -> binary().
enc_private_key_cert(#'ECPrivateKey'{parameters = {namedCurve, ?'id-Ed25519'},
				     privateKey = Priv, publicKey = Pub}) ->
    list_to_binary([enc_b(Pub), enc_b([Priv, Pub])]);
enc_private_key_cert(#'RSAPrivateKey'{privateExponent = D,
				      coefficient = IQMP,
				      prime1 = P,
				      prime2 = Q}) ->
    list_to_binary(lists:map(fun mpint/1, [D,IQMP,P,Q]));

enc_private_key_cert(#'ECPrivateKey'{parameters = {namedCurve, Oid},
				     privateKey = Priv})
  when Oid == ?secp256r1 ;
       Oid == ?secp384r1 ;
       Oid == ?secp521r1 ->
    enc_b(Priv);
enc_private_key_cert(#'DSAPrivateKey'{x = X}) -> mpint(X).


-spec enc_private_key(essh_private_key()) -> binary().
enc_private_key(#'RSAPrivateKey'{modulus = N,
				 publicExponent = E,
				 privateExponent = D,
				 coefficient = IQMP,
				 prime1 = P,
				 prime2 = Q}) ->
    L = [N, E, D, IQMP, P, Q],
    list_to_binary([enc_b("ssh-rsa") | lists:map(fun mpint/1, L)]);
enc_private_key(#'DSAPrivateKey'{p = P, q = Q, g = G, y = Y, x = X}) ->
    L = [P, Q, G, X, Y],
    list_to_binary([enc_b("ssh-dss") | lists:map(fun mpint/1, L)]);
enc_private_key(#'ECPrivateKey'{parameters = {namedCurve, ?'id-Ed25519'},
				privateKey = Priv, publicKey = Pub}) ->
    list_to_binary([enc_b("ssh-ed25519"), enc_b(Pub), enc_b([Priv, Pub])]);
enc_private_key(#'ECPrivateKey'{parameters = {namedCurve, Oid},
				privateKey = Priv, publicKey = Pub })
  when Oid == ?secp256r1 ;
       Oid == ?secp384r1 ;
       Oid == ?secp521r1 ->
    C = oid2curvename(Oid),
    list_to_binary([enc_b([<<"ecdsa-sha2-">>,C]), enc_b(C),
		    enc_b(Pub), enc_b(Priv)]).


enc_pubkey(#'RSAPublicKey'{modulus = N, publicExponent = E}) ->
    list_to_binary([mpint(E), mpint(N)]);
enc_pubkey({Y,  #'Dss-Parms'{p = P, q = Q, g = G}}) ->
    list_to_binary([mpint(P), mpint(Q), mpint(G), mpint(Y)]);
enc_pubkey({ #'ECPoint'{ point = PK }, {namedCurve, ?'id-Ed25519'} }) -> enc_b(PK);
enc_pubkey({ #'ECPoint'{ point = PK }, {namedCurve, Oid} }) ->
    list_to_binary([enc_b(oid2curvename(Oid)), enc_b(PK)]).



curvename2oid(<<"nistp256">>) -> ?secp256r1;
curvename2oid(<<"nistp384">>) -> ?secp384r1;
curvename2oid(<<"nistp521">>) -> ?secp521r1.


oid2curvename(?secp256r1) -> <<"nistp256">>;
oid2curvename(?secp384r1) -> <<"nistp384">>;
oid2curvename(?secp521r1) -> <<"nistp521">>.

digest_type(<<"ecdsa-sha2-nistp256">>) -> sha256;
digest_type(<<"ecdsa-sha2-nistp384">>) -> sha384;
digest_type(<<"ecdsa-sha2-nistp521">>) -> sha512;
digest_type(<<"ssh-dss">>) -> sha;
digest_type(<<"ssh-ed25519">>) -> none;
digest_type(<<"rsa-sha2-512">>) -> sha512;
digest_type(<<"rsa-sha2-256">>) -> sha256;
digest_type(<<"ssh-rsa">>) -> sha.


key_type(#'RSAPublicKey'{}) -> <<"ssh-rsa">>;
key_type({_, #'Dss-Parms'{}}) -> <<"ssh-dss">>;
key_type({#'ECPoint'{}, {namedCurve, ?'id-Ed25519'}}) -> <<"ssh-ed25519">>;
key_type({#'ECPoint'{}, {namedCurve, Oid }}) ->
    <<"ecdsa-sha2-",(oid2curvename(Oid))/binary>>.


enc_b(L) when is_list(L) -> enc_b(list_to_binary(L));
enc_b(B) when is_binary(B) -> <<(size(B)):32, B/binary>>.


enc_cert_type(user) -> <<1:32>>;
enc_cert_type(host) -> <<2:32>>.


dec_cert_type(1) -> user;
dec_cert_type(2) -> host.


dec_sl(<<>>, Acc) -> lists:reverse(Acc);
dec_sl(<<Len:32, String:Len/binary, Rest/binary>>, Acc) ->
    dec_sl(Rest, [String|Acc]).


dec_kvs(<<>>, Acc) -> lists:reverse(Acc);
dec_kvs(<<KeyLen:32, Key:KeyLen/binary,
	  ValueLen:32, Value:ValueLen/binary,
	  Rest/binary>>, Acc) ->
    dec_kvs(Rest, [{Key,Value}|Acc]).


enc_kvs(L0) ->
    enc_b(
      lists:map(
	fun({K, V}) ->
		<<(enc_b(K))/binary, (enc_b(V))/binary>> end, L0)).


-spec dec_sig(binary()) -> {binary(), binary()}.
dec_sig(<<InfoLen:32, Info:InfoLen/binary, SigLen:32, Sig:SigLen/binary>>) ->
    {Info, Sig}.



%%%----------------------------------------------------------------
%%% Multi Precision Integer encoding
%%% copied from lib/ssh-4.14/src/ssh_bits.erl
%%% which is Copyright Ericsson AB 2005-2016. All Rights Reserved.
%%% and Licensed under the Apache License, Version 2.0

mpint(-1) -> <<0,0,0,1,16#ff>>;
mpint(0) -> <<0,0,0,0>>;
mpint(I) when I>0 ->
    <<B1,V/binary>> = binary:encode_unsigned(I),
    case B1 band 16#80 of
        16#80 ->
            <<(size(V)+2):32/unsigned-big-integer, 0,B1,V/binary >>;
        _ ->
            <<(size(V)+1):32/unsigned-big-integer, B1,V/binary >>
    end;
mpint(N) when N<0 ->
    Sxn =  8*size(binary:encode_unsigned(-N)),
    Sxn1 = Sxn+8,
    <<W:Sxn1>> = <<1, 0:Sxn>>,
    <<B1,V/binary>> = binary:encode_unsigned(W+N),
    case B1 band 16#80 of
        16#80 ->
            <<(size(V)+1):32/unsigned-big-integer, B1,V/binary >>;
        _ ->
            <<(size(V)+2):32/unsigned-big-integer, 255,B1,V/binary >>
    end.

%%%----------------------------------------------------------------
