-module(essh_pkt).

-export([dec_signature_key/1,
	 enc_signature_key/1,
	 enc_private_key/1]).

-include_lib("public_key/include/public_key.hrl").

-type essh_public_key() :: public_key:rsa_public_key() |
			   public_key:dsa_public_key() |
			   public_key:ec_public_key() |
			   public_key:ed_public_key().

-type essh_private_key() :: public_key:rsa_private_key() |
			    public_key:dsa_private_key() |
			    public_key:ec_private_key() |
			    public_key:ed_private_key().


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
    L = [P, Q, G, Y, X],
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


key_type(#'RSAPublicKey'{}) -> <<"ssh-rsa">>;
key_type({_, #'Dss-Parms'{}}) -> <<"ssh-dss">>;
key_type({#'ECPoint'{}, {namedCurve, ?'id-Ed25519'}}) -> <<"ssh-ed25519">>;
key_type({#'ECPoint'{}, {namedCurve, Oid }}) ->
    <<"ecdsa-sha2-",(oid2curvename(Oid))/binary>>.


enc_b(L) when is_list(L) -> enc_b(list_to_binary(L));
enc_b(B) when is_binary(B) -> <<(size(B)):32, B/binary>>.


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
