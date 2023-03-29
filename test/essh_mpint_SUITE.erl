-module(essh_mpint_SUITE).

-export([all/0, init_per_suite/1, end_per_suite/1, prop_mpint_case/1]).

-include_lib("common_test/include/ct.hrl").

all() ->
    [prop_mpint_case].

init_per_suite(Config) ->
    ct_property_test:init_per_suite(Config).

end_per_suite(Config) ->
    Config.

prop_mpint_case(Config) ->
    ct_property_test:quickcheck(prop_mpint:prop_enc(), Config).
