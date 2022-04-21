essh_agent
=====

An OTP library

Build
-----

    $ rebar3 compile


Test
----

    $ rebar3 as test do dialyzer,xref,ct,proper,cover
