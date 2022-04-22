-module(essh_pkt).

-export([dec_signature_key/1,
	 enc_signature_key/1,
	 enc_private_key_cert/1,
	 enc_private_key/1]).

-export([enc_cert/1, dec_cert/1]).

-export([enc_constraints/1]).

-export([enc_tbs/1, key_type/1, oid2curvename/1, mpint/1]).

-export([enc_identities_answer/1, dec_add_id/1, dec_key_or_cert/1]).

-include_lib("public_key/include/public_key.hrl").
-include("essh_agent_constants.hrl").
-include("essh_binary.hrl").

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

-type essh_constraint() :: confirm |
			   {lifetime, Seconds :: pos_integer()} |
			   Extension :: {Name :: binary(), Value :: binary()}.

-export_type([essh_public_key/0, essh_private_key/0, essh_certificate/0,
	      essh_constraint/0]).

-spec enc_identities_answer([{essh_certificate() | essh_public_key(),
			      Comment ::binary()}]) -> binary().
enc_identities_answer(L) ->
    list_to_binary(
      [<<?UINT32(length(L))>> |
       lists:map(
	 fun({#{cert_type := _} = Cert, Comment}) ->
		 <<?BINARY((enc_cert(Cert))), ?BINARY(Comment)>>;
	    ({PK, Comment}) ->
		 <<?BINARY((enc_signature_key(PK))), ?BINARY(Comment)>>
	 end, L)]).

-spec dec_key_or_cert(binary()) -> essh_public_key() | essh_certificate().
dec_key_or_cert(<<?BINARY(TypeInfo, _TypeInfoLen), _/binary>> = Bin)
  when TypeInfo == <<"ssh-ed25519-cert-v01@openssh.com">> ;
       TypeInfo == <<"ssh-rsa-cert-v01@openssh.com">> ;
       TypeInfo == <<"rsa-sha2-256-cert-v01@openssh.com">> ;
       TypeInfo == <<"rsa-sha2-512-cert-v01@openssh.com">> ;
       TypeInfo == <<"ssh-dss-cert-v01@openssh.com">> ;
       TypeInfo == <<"ecdsa-sha2-nistp256-cert-v01@openssh.com">>;
       TypeInfo == <<"ecdsa-sha2-nistp384-cert-v01@openssh.com">>;
       TypeInfo == <<"ecdsa-sha2-nistp521-cert-v01@openssh.com">> ->
    dec_cert(Bin);
dec_key_or_cert(Bin) -> dec_signature_key(Bin).


-spec dec_add_id(binary()) ->
	  {essh_private_key(), Comment :: binary(),
	   [essh_constraint()]} |
	  {essh_private_key(), essh_certificate(), Comment :: binary(),
	   [essh_constraint()]}.
dec_add_id(<<?BINARY(TypeInfo, _TypeInfoLen),
	     ?BINARY(CertBlob, _CertBlobLen),
	     Rest/binary>>)
  when TypeInfo == <<"ssh-ed25519-cert-v01@openssh.com">> ;
       TypeInfo == <<"ssh-rsa-cert-v01@openssh.com">> ;
       TypeInfo == <<"rsa-sha2-256-cert-v01@openssh.com">> ;
       TypeInfo == <<"rsa-sha2-512-cert-v01@openssh.com">> ;
       TypeInfo == <<"ssh-dss-cert-v01@openssh.com">> ;
       TypeInfo == <<"ecdsa-sha2-nistp256-cert-v01@openssh.com">>;
       TypeInfo == <<"ecdsa-sha2-nistp384-cert-v01@openssh.com">>;
       TypeInfo == <<"ecdsa-sha2-nistp521-cert-v01@openssh.com">> ->
    dec_add_id_c(dec_cert(CertBlob), TypeInfo,Rest);
dec_add_id(<<?BINARY(TypeInfo, _TypeInfoLen),
	     ?MPINT(N, _NLen), ?MPINT(E, _ELen), ?MPINT(D, _DLen),
	     ?MPINT(IQMP, _IQMPLen), ?MPINT(P, _PLen), ?MPINT(Q, _QLen),
	     ?BINARY(Comment, _CommentLen), Constraints/binary>>)
  when TypeInfo == <<"ssh-rsa">> ->
    Key = #'RSAPrivateKey'{modulus = N,
			   publicExponent = E,
			   privateExponent = D,
			   coefficient = IQMP,
			   prime1 = P,
			   prime2 = Q},
    {Key, Comment, dec_constraints(Constraints)};
dec_add_id(<<?BINARY(TypeInfo, _TypeInfoLen),
	     ?MPINT(P, _PLen), ?MPINT(Q, _QLen), ?MPINT(G, _GLen),
	     ?MPINT(X, _XLen), ?MPINT(Y, YLen),
	     ?BINARY(Comment, _CommentLen), Constraints/binary>>)
  when TypeInfo == <<"ssh-dss">> ->
    Key = #'DSAPrivateKey'{p = P, q = Q, g = G, y = Y, x = X},
    {Key, Comment, dec_constraints(Constraints)};
dec_add_id(<<?BINARY(TypeInfo, _TypeInfoLen),
	     ?BINARY(PK, PKLen), ?BINARY(PrivPub, PrivPubLen),
	     ?BINARY(Comment, _CommentLen), Constraints/binary>>)
  when TypeInfo == <<"ssh-ed25519">> ->
    <<Priv:(PrivPubLen - PKLen)/binary, PK:PKLen/binary>> = PrivPub,
    Key = #'ECPrivateKey'{parameters = {namedCurve, ?'id-Ed25519'},
			  privateKey = Priv, publicKey = PK},
    {Key, Comment, dec_constraints(Constraints)};
dec_add_id(<<?BINARY(TypeInfo, _TypeInfoLen),
	     ?BINARY(C, _CLen), ?BINARY(Pub, _PubLen), ?BINARY(Priv, _PrivLen),
	     ?BINARY(Comment, _CommentLen), Constraints/binary>>)
  when (TypeInfo == <<"ecdsa-sha2-nistp256">>) andalso (C == <<"nistp256">>);
       (TypeInfo == <<"ecdsa-sha2-nistp384">>) andalso (C == <<"nistp384">>);
       (TypeInfo == <<"ecdsa-sha2-nistp521">>) andalso (C == <<"nistp521">>) ->
    Key = #'ECPrivateKey'{parameters = {namedCurve, curvename2oid(C)},
			  privateKey = Priv, publicKey = Pub},
    {Key, Comment, dec_constraints(Constraints)}.


dec_add_id_c(#{type_info := TypeInfo,
	       public_key := {#'ECPoint'{point = PK},
			      {namedCurve, ?'id-Ed25519'} = Curve}} = Cert,
	     TypeInfo,
	     <<?BINARY(PK, PKLen), ?BINARY(PrivPub, PrivPubLen),
	       ?BINARY(Comment, _CommentLen), Constraints/binary>>) ->
    <<Priv:(PrivPubLen - PKLen)/binary, PK:PKLen/binary>> = PrivPub,
    Key = #'ECPrivateKey'{parameters = Curve, privateKey = Priv, publicKey = PK},
    {Key, Cert, Comment, dec_constraints(Constraints)};
dec_add_id_c(#{type_info := TypeInfo,
	       public_key := {#'ECPoint'{point = PK},
			      {namedCurve, Oid} = Curve}} = Cert,
	     TypeInfo,
	     <<?BINARY(Priv, _PrivLen),
	       ?BINARY(Comment, _CommentLen), Constraints/binary>>) when
      Oid == ?secp256r1 ; Oid == ?secp384r1 ; Oid == ?secp521r1 ->
    Key = #'ECPrivateKey'{parameters = Curve, privateKey = Priv, publicKey = PK},
    {Key, Cert, Comment, dec_constraints(Constraints)};
dec_add_id_c(#{type_info := TypeInfo,
	       public_key := {Y, #'Dss-Parms'{p = P, q = Q, g = G}}} = Cert,
	     TypeInfo,
	     <<?MPINT(X, _XLen),
	       ?BINARY(Comment, _CommentLen), Constraints/binary>>) ->
    Key = #'DSAPrivateKey'{p = P, q = Q, g = G, y = Y, x = X},
    {Key, Cert, Comment, dec_constraints(Constraints)};
dec_add_id_c(#{type_info := TypeInfo,
	       public_key := #'RSAPublicKey'{modulus = N
					    ,publicExponent = E}} = Cert,
	     TypeInfo,
	     <<?MPINT(D, _DLen), ?MPINT(IQMP, _IQMPLen),
	       ?MPINT(P, _PLen), ?MPINT(Q, _QLen),
	       ?BINARY(Comment, _CommentLen), Constraints/binary>>) ->
    Key = #'RSAPrivateKey'{version = 'two-prime',
			   modulus = N,
			   publicExponent = E,
			   privateExponent = D,
			   coefficient = IQMP,
			   prime1 = P,
			   prime2 = Q},
    {Key, Cert, Comment, dec_constraints(Constraints)}.


-spec dec_constraints(binary()) -> [essh_constraint()].
dec_constraints(CS) -> dec_constraints1(CS, []).

dec_constraints1(<<>>, Acc) ->
    Acc;
dec_constraints1(<<?BYTE(?SSH_AGENT_CONSTRAIN_CONFIRM), Rest/binary>>, Acc) ->
    dec_constraints1(Rest, [confirm|Acc]);
dec_constraints1(<<?BYTE(?SSH_AGENT_CONSTRAIN_LIFETIME),
		   ?UINT32(Seconds), Rest/binary>>, Acc) ->
    dec_constraints1(Rest, [{lifetime, Seconds}|Acc]);
dec_constraints1(<<?BYTE(?SSH_AGENT_CONSTRAIN_EXTENSION),
		   ?BINARY(Name, _NameLen), ?BINARY(Value, ValueLen),
		   Rest/binary>>, Acc) ->
    dec_constraints1(Rest, [{Name, Value}|Acc]).


-spec enc_constraints([essh_constraint()]) -> binary().
enc_constraints(L) -> list_to_binary([enc_constraint(V) || V <- L]).

enc_constraint(confirm) -> <<?BYTE(?SSH_AGENT_CONSTRAIN_CONFIRM)>>;
enc_constraint({lifetime, Seconds}) when is_integer(Seconds), Seconds > 0 ->
    <<?BYTE(?SSH_AGENT_CONSTRAIN_LIFETIME), ?UINT32(Seconds)>>;
enc_constraint({Name, Value}) when is_binary(Name), is_binary(Value) ->
    <<?BYTE(?SSH_AGENT_CONSTRAIN_EXTENSION), ?BINARY(Name), ?BINARY(Value) >>.


-spec enc_cert(essh_certificate()) -> binary().
enc_cert(#{signature := {SignInfo, Signature}} = Cert) ->
    SignatureBlob = <<?BINARY(SignInfo), ?BINARY(Signature)>>,
    <<(enc_tbs(Cert))/binary, ?BINARY(SignatureBlob)>>.


-spec dec_cert(binary()) -> essh_certificate().
dec_cert(<<?BINARY(TypeInfo, _TypeInfoLen), ?BINARY(Nonce, _NonceLen),
	   ?BINARY(PK, _PKLen), Rest/binary>>)
  when TypeInfo == <<"ssh-ed25519-cert-v01@openssh.com">> ->
    M = dec_cert_common(Rest),
    M#{type_info => TypeInfo,
       nonce => Nonce,
       public_key => {#'ECPoint'{point = PK}, {namedCurve, ?'id-Ed25519'}}};
dec_cert(<<?BINARY(TypeInfo, _TypeInfoLen), ?BINARY(Nonce, _NonceLen),
	   ?MPINT(E, _Elen), ?MPINT(N, _NLen), Rest/binary>>)
  when TypeInfo == <<"ssh-rsa-cert-v01@openssh.com">>;
       TypeInfo == <<"rsa-sha2-256-cert-v01@openssh.com">>;
       TypeInfo == <<"rsa-sha2-512-cert-v01@openssh.com">> ->
    M = dec_cert_common(Rest),
    M#{type_info => TypeInfo,
       nonce => Nonce,
       public_key => #'RSAPublicKey'{modulus = N, publicExponent = E}};
dec_cert(<<?BINARY(TypeInfo, _TypeInfoLen), ?BINARY(Nonce, _NonceLen),
	   ?MPINT(P, _PLen), ?MPINT(Q, _QLen), ?MPINT(G, _GLen),
	   ?MPINT(Y, _YLen), Rest/binary>>)
  when TypeInfo == <<"ssh-dss-cert-v01@openssh.com">> ->
    M = dec_cert_common(Rest),
    M#{type_info => TypeInfo,
       nonce => Nonce,
       public_key => {Y, #'Dss-Parms'{p = P, q = Q, g = G}}};
dec_cert(<<?BINARY(TypeInfo, _TypeInfoLen), ?BINARY(Nonce, _NonceLen),
	   ?BINARY(Curve, _CurveLen), ?BINARY(PK, _PKLen), Rest/binary>>)
  when TypeInfo == <<"ecdsa-sha2-nistp256-cert-v01@openssh.com">>;
       TypeInfo == <<"ecdsa-sha2-nistp384-cert-v01@openssh.com">>;
       TypeInfo == <<"ecdsa-sha2-nistp521-cert-v01@openssh.com">> ->
    M = dec_cert_common(Rest),
    M#{type_info => TypeInfo,
       nonce => Nonce,
       public_key => {#'ECPoint'{point = PK},
		      {namedCurve, curvename2oid(Curve)}}}.

dec_cert_common(<<?UINT64(Serial),
                  ?UINT32(CertType),
		  ?BINARY(KeyId, _KeyIdLen),
		  ?BINARY(ValidPrincipals, _ValidPrincipalsLen),
		  ?UINT64(ValidAfter),
		  ?UINT64(ValidBefore),
		  ?BINARY(CriticalOptions, _CriticalOptionsLen),
		  ?BINARY(Extensions, _ExtensionsLen),
		  ?BINARY(Reserved, _ReservedLen),
		  ?BINARY(SignatureKey, _SignatureKeyLen),
		  ?BINARY(SignatureBlob, _SignatureBlobLen)>>) ->
    <<?BINARY(SignInfo, _SignInfoLen),
      ?BINARY(Signature, _SignatureLen)>> = SignatureBlob,
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
      signature => {SignInfo, Signature}}.



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
    <<?BINARY(TypeInfo),
      ?BINARY(Nonce),
      (enc_pubkey(PublicKey))/binary,
      ?UINT64(Serial),
      (enc_cert_type(CertType))/binary, ?BINARY(KeyId),
      ?BINARY((enc_sl(ValidPrincipals))),
      ?UINT64(ValidAfter),
      ?UINT64(ValidBefore),
      ?BINARY((enc_kvs(CriticalOptions))),
      ?BINARY((enc_kvs(Extensions))),
      ?BINARY(Reserved),
      ?BINARY((enc_signature_key(SignatureKey)))>>.


-spec dec_signature_key(binary()) -> essh_public_key().
dec_signature_key(<<?BINARY(SigKInfo, _SigKInfoLen),
		    ?MPINT(E, _ELen), ?MPINT(N, _NLen)>>)
  when SigKInfo == <<"ssh-rsa">> ->
    #'RSAPublicKey'{ modulus = N, publicExponent = E};
dec_signature_key(<<?BINARY(SigKInfo, _SigKInfoLen),
		    ?MPINT(P, _PLen), ?MPINT(Q, _QLen), ?MPINT(G, _GLen),
		    ?MPINT(Y, _YLen)>>)
  when SigKInfo == <<"ssh-dss">> ->
    {Y, #'Dss-Parms'{p = P, q = Q, g = G}};
dec_signature_key(<<?BINARY(SigKInfo, _SigKInfoLen),
		    ?BINARY(PK, _PKLen)>>)
  when SigKInfo == <<"ssh-ed25519">> ->
    { #'ECPoint'{ point = PK }, {namedCurve, ?'id-Ed25519'} };
dec_signature_key(<<?BINARY(SigKInfo, _SigKInfoLen),
		    ?BINARY(Curve, _CurveLen), ?BINARY(PK, _PKLen)>>)
  when SigKInfo == <<"ecdsa-sha2-nistp256">> ;
       SigKInfo == <<"ecdsa-sha2-nistp384">> ;
       SigKInfo == <<"ecdsa-sha2-nistp521">> ->
    {#'ECPoint'{ point = PK }, {namedCurve, curvename2oid(Curve)} }.


-spec enc_signature_key(essh_public_key()) -> binary().
enc_signature_key(SignatureKey) ->
    <<?BINARY((key_type(SignatureKey))), (enc_pubkey(SignatureKey))/binary>>.


-spec enc_private_key_cert(essh_private_key()) -> binary().
enc_private_key_cert(#'ECPrivateKey'{parameters = {namedCurve, ?'id-Ed25519'},
				     privateKey = Priv, publicKey = Pub}) ->
    <<?BINARY(Pub), ?BINARY(<<Priv/binary, Pub/binary>>)>>;
enc_private_key_cert(#'RSAPrivateKey'{privateExponent = D,
				      coefficient = IQMP,
				      prime1 = P,
				      prime2 = Q}) ->
    list_to_binary([mpint(V) || V <- [D,IQMP,P,Q]]);
enc_private_key_cert(#'ECPrivateKey'{parameters = {namedCurve, Oid},
				     privateKey = Priv})
  when Oid == ?secp256r1 ; Oid == ?secp384r1 ; Oid == ?secp521r1 ->
    <<?BINARY(Priv)>>;
enc_private_key_cert(#'DSAPrivateKey'{x = X}) -> mpint(X).


-spec enc_private_key(essh_private_key()) -> binary().
enc_private_key(#'RSAPrivateKey'{modulus = N,
				 publicExponent = E,
				 privateExponent = D,
				 coefficient = IQMP,
				 prime1 = P,
				 prime2 = Q}) ->
    L = [N, E, D, IQMP, P, Q],
    <<?BINARY(<<"ssh-rsa">>), (list_to_binary([mpint(V)||V<-L]))/binary>>;
enc_private_key(#'DSAPrivateKey'{p = P, q = Q, g = G, y = Y, x = X}) ->
    L = [P, Q, G, X, Y],
    <<?BINARY(<<"ssh-dss">>), (list_to_binary([mpint(V)||V<-L]))/binary>>;
enc_private_key(#'ECPrivateKey'{parameters = {namedCurve, ?'id-Ed25519'},
				privateKey = Priv, publicKey = Pub}) ->
    <<?BINARY(<<"ssh-ed25519">>), ?BINARY(Pub),
      ?BINARY(<<Priv/binary, Pub/binary>>)>>;
enc_private_key(#'ECPrivateKey'{parameters = {namedCurve, Oid},
				privateKey = Priv, publicKey = Pub })
  when Oid == ?secp256r1 ; Oid == ?secp384r1 ; Oid == ?secp521r1 ->
    C = oid2curvename(Oid),
    <<?BINARY(<<"ecdsa-sha2-", C/binary>>),
      ?BINARY(C), ?BINARY(Pub), ?BINARY(Priv)>>.


enc_pubkey(#'RSAPublicKey'{modulus = N, publicExponent = E}) ->
    list_to_binary([mpint(E), mpint(N)]);
enc_pubkey({Y,  #'Dss-Parms'{p = P, q = Q, g = G}}) ->
    list_to_binary([mpint(P), mpint(Q), mpint(G), mpint(Y)]);
enc_pubkey({ #'ECPoint'{ point = PK }, {namedCurve, ?'id-Ed25519'} }) -> <<?BINARY(PK)>>;
enc_pubkey({ #'ECPoint'{ point = PK }, {namedCurve, Oid} }) ->
    <<?BINARY((oid2curvename(Oid))), ?BINARY(PK)>>.


curvename2oid(<<"nistp256">>) -> ?secp256r1;
curvename2oid(<<"nistp384">>) -> ?secp384r1;
curvename2oid(<<"nistp521">>) -> ?secp521r1.


-spec oid2curvename(?secp256r1 | ?secp384r1 | ?secp521r1) -> binary().
oid2curvename(?secp256r1) -> <<"nistp256">>;
oid2curvename(?secp384r1) -> <<"nistp384">>;
oid2curvename(?secp521r1) -> <<"nistp521">>.


-spec key_type(essh_public_key()) -> binary().
key_type(#'RSAPublicKey'{}) -> <<"ssh-rsa">>;
key_type({_, #'Dss-Parms'{}}) -> <<"ssh-dss">>;
key_type({#'ECPoint'{}, {namedCurve, ?'id-Ed25519'}}) -> <<"ssh-ed25519">>;
key_type({#'ECPoint'{}, {namedCurve, Oid }}) ->
    <<"ecdsa-sha2-",(oid2curvename(Oid))/binary>>.


enc_cert_type(user) -> <<?UINT32(1)>>;
enc_cert_type(host) -> <<?UINT32(2)>>.


dec_cert_type(1) -> user;
dec_cert_type(2) -> host.


enc_sl(L) -> list_to_binary([<<?BINARY(V)>> || V <- L]).

dec_sl(<<>>, Acc) -> lists:reverse(Acc);
dec_sl(<<?BINARY(S, _SLen), Rest/binary>>, Acc) -> dec_sl(Rest, [S|Acc]).


enc_kvs(KvS) -> list_to_binary([<<?BINARY(K), ?BINARY(V)>> || {K,V} <- KvS]).

dec_kvs(<<>>, Acc) -> lists:reverse(Acc);
dec_kvs(<<?BINARY(K, _KLen), ?BINARY(V, _VLen), Rest/binary>>, Acc) ->
    dec_kvs(Rest, [{K,V}|Acc]).


%%%----------------------------------------------------------------
%%% Multi Precision Integer encoding
%%% copied from lib/ssh-4.14/src/ssh_bits.erl
%%% which is Copyright Ericsson AB 2005-2016. All Rights Reserved.
%%% and Licensed under the Apache License, Version 2.0

-spec mpint(integer()) -> <<_:32, _:_*8>>.
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
