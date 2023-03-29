-module(prop_mpint).

-export([prop_enc/0]).

-include_lib("common_test/include/ct_property_test.hrl").

prop_enc() ->
    ?FORALL(
        MPINT,
        gen_mpint(),
        begin
            check(MPINT)
        end
    ).

check({I, <<ILen:32, I:ILen/big-signed-integer-unit:8>>}) -> true;
check(_) -> false.

gen_mpint() -> ?LET(I, largeint(), {I, essh_pkt:mpint(I)}).
