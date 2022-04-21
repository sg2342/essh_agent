-module(prop_mpint).

-export([prop_mpint/0]).

-include_lib("common_test/include/ct_property_test.hrl").

-include_lib("proper/include/proper.hrl").

prop_mpint() ->
    ?FORALL(MPINT, gen_mpint(),
	    begin
		check(MPINT)
	    end).

check({I, <<ILen:32, I:ILen/big-signed-integer-unit:8>>}) -> true;
check(_) -> false.

gen_mpint() -> ?LET(I, largeint(), {I, essh_pkt:mpint(I)}).
