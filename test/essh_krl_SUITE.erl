-module(essh_krl_SUITE).

-include_lib("common_test/include/ct.hrl").

-export([
    all/0,
    init_per_suite/1,
    end_per_suite/1,
    init_per_testcase/2,
    end_per_testcase/2
]).

-export([
    dec_empty/1,
    dec_explicit_key/1,
    dec_fingerprint_sha1/1,
    dec_fingerprint_sha256/1,
    dec_cert_serial_list/1,
    dec_cert_serial_range/1,
    dec_cert_serial_bitmap/1,
    dec_cert_key_id/1,
    enc_empty/1,
    enc_explicit_key/1,
    enc_fingerprint_sha1/1,
    enc_fingerprint_sha256/1,
    enc_cert_serial_list/1,
    enc_cert_serial_range/1,
    enc_cert_serial_bitmap/1,
    enc_cert_key_id/1,
    extensions/1
]).

all() ->
    [
        dec_empty,
        dec_explicit_key,
        dec_fingerprint_sha1,
        dec_fingerprint_sha256,
        dec_cert_serial_list,
        dec_cert_serial_range,
        dec_cert_serial_bitmap,
        dec_cert_key_id,
        enc_empty,
        enc_explicit_key,
        enc_fingerprint_sha1,
        enc_fingerprint_sha256,
        enc_cert_serial_list,
        enc_cert_serial_range,
        enc_cert_serial_bitmap,
        enc_cert_key_id,
        extensions
    ].

init_per_suite(Config) ->
    {ok, Started} = application:ensure_all_started(public_key),
    Dir = filename:join(?config(priv_dir, Config), atom_to_list(?MODULE)),
    KRLFile = filename:join(Dir, "KRL"),
    SpecFile = filename:join(Dir, "SPEC"),
    filelib:ensure_dir(KRLFile),
    PubKeyFile = filename:join(?config(data_dir, Config), "id_ed25519.pub"),
    {ok, B} = file:read_file(PubKeyFile),
    [{PubKey, _}] = ssh_file:decode(B, public_key),
    [
        {started_applications, Started},
        {krl_file, KRLFile},
        {spec_file, SpecFile},
        {pub_key_file, PubKeyFile},
        {pub_key, PubKey}
        | Config
    ].

end_per_suite(Config0) ->
    {value, {_, Started}, Config} = lists:keytake(started_applications, 1, Config0),
    lists:foreach(fun application:stop/1, lists:reverse(Started)),
    Config.

init_per_testcase(_TC, Config) ->
    Config.

end_per_testcase(_TC, Config) -> Config.

enc_empty(Config) ->
    enc_krl(Config, #{
        krl_version => 1,
        generated_date => os:system_time(second),
        flags => 0,
        reserved => <<>>,
        comment => <<"this one is empty">>,
        sections => []
    }),
    {0, "# KRL version 1\n#" ++ _} = check_krl(Config, ["-l"]).

enc_explicit_key(Config) ->
    PubKeyFile = ?config(pub_key_file, Config),
    enc_krl(Config, #{
        krl_version => 1,
        generated_date => os:system_time(second),
        flags => 0,
        reserved => <<>>,
        comment => <<>>,
        sections => [{explicit_key, [?config(pub_key, Config)]}]
    }),
    check_revoked(Config, PubKeyFile).

enc_fingerprint_sha1(Config) ->
    PubKeyFile = ?config(pub_key_file, Config),
    Sha1 = hash_pub_key(Config, sha),
    enc_krl(Config, #{
        krl_version => 2,
        generated_date => os:system_time(second),
        flags => 0,
        reserved => <<>>,
        comment => <<>>,
        sections => [{fingerprint_sha1, [Sha1]}]
    }),
    check_revoked(Config, PubKeyFile).

enc_fingerprint_sha256(Config) ->
    PubKeyFile = ?config(pub_key_file, Config),
    Sha256 = hash_pub_key(Config, sha256),
    enc_krl(Config, #{
        krl_version => 3,
        generated_date => os:system_time(second),
        flags => 0,
        reserved => <<>>,
        comment => <<>>,
        sections => [{fingerprint_sha256, [Sha256]}]
    }),
    check_revoked(Config, PubKeyFile).

enc_cert_serial_list(Config) ->
    CertFile = filename:join(?config(data_dir, Config), "id_ed25519-cert.pub"),
    enc_krl(Config, #{
        krl_version => 4,
        generated_date => os:system_time(second),
        flags => 0,
        reserved => <<>>,
        comment => <<>>,
        sections => [
            {certificates, #{
                ca_key => undefined, reserved => <<>>, sections => [{serial_list, [2342]}]
            }}
        ]
    }),
    check_revoked(Config, CertFile).

enc_cert_serial_range(Config) ->
    CertFile = filename:join(?config(data_dir, Config), "id_ed25519-cert.pub"),
    enc_krl(Config, #{
        krl_version => 4,
        generated_date => os:system_time(second),
        flags => 0,
        reserved => <<>>,
        comment => <<>>,
        sections => [
            {certificates, #{
                ca_key => undefined,
                reserved => <<>>,
                sections => [{serial_range, #{min => 1, max => 18446744073709551615}}]
            }}
        ]
    }),
    check_revoked(Config, CertFile).

enc_cert_serial_bitmap(Config) ->
    CertFile = filename:join(?config(data_dir, Config), "id_ed25519-cert.pub"),
    enc_krl(Config, #{
        krl_version => 4,
        generated_date => os:system_time(second),
        flags => 0,
        reserved => <<>>,
        comment => <<>>,
        sections => [
            {certificates, #{
                ca_key => undefined,
                reserved => <<>>,
                sections => [{serial_bitmap, #{offset => 2342, bitmap => <<1>>}}]
            }}
        ]
    }),
    check_revoked(Config, CertFile).

enc_cert_key_id(Config) ->
    CertFile = filename:join(?config(data_dir, Config), "id_ed25519-cert.pub"),
    enc_krl(Config, #{
        krl_version => 4,
        generated_date => os:system_time(second),
        flags => 0,
        reserved => <<>>,
        comment => <<>>,
        sections => [
            {certificates, #{
                ca_key => ?config(pub_key, Config),
                reserved => <<>>,
                sections => [{key_id, [<<"foo@bar">>]}]
            }}
        ]
    }),
    check_revoked(Config, CertFile).

dec_empty(Config) ->
    {0, _} = gen_krl_spec(Config, 1, []),
    #{krl_version := 1, sections := []} = dec_krl(Config).

dec_explicit_key(Config) ->
    Pub = ?config(pub_key, Config),
    {0, _} = gen_krl(Config, 2, [?config(pub_key_file, Config)]),
    #{krl_version := 2, sections := [{explicit_key, [Pub]}]} = dec_krl(Config).

dec_fingerprint_sha1(Config) ->
    {ok, PubKeyB} = file:read_file(?config(pub_key_file, Config)),
    {0, _} = gen_krl_spec(Config, 3, ["sha1:", PubKeyB]),
    Sha1 = hash_pub_key(Config, sha),
    #{
        krl_version := 3,
        sections := [{fingerprint_sha1, [Sha1]}]
    } = dec_krl(Config).

dec_fingerprint_sha256(Config) ->
    {ok, PubKeyB} = file:read_file(?config(pub_key_file, Config)),
    {0, _} = gen_krl_spec(Config, 4, ["sha256: ", PubKeyB]),
    Sha256 = hash_pub_key(Config, sha256),
    #{
        krl_version := 4,
        sections := [{fingerprint_sha256, [Sha256]}]
    } =
        dec_krl(Config).

dec_cert_serial_list(Config) ->
    Pub = ?config(pub_key, Config),
    {0, _} = gen_krl_spec(Config, 5, ["-s", ?config(pub_key_file, Config)], ["serial: 23\n"]),
    #{
        krl_version := 5,
        sections := [{certificates, #{ca_key := Pub, sections := [{serial_list, [23]}]}}]
    } = dec_krl(Config).

dec_cert_serial_range(Config) ->
    Pub = ?config(pub_key, Config),
    {0, _} = gen_krl_spec(Config, 6, ["-s", ?config(pub_key_file, Config)], [
        "serial: 1-18446744073709551615\n"
    ]),
    #{
        krl_version := 6,
        sections := [
            {certificates, #{
                ca_key := Pub,
                sections := [{serial_range, #{min := 1, max := 18446744073709551615}}]
            }}
        ]
    } = dec_krl(Config).

dec_cert_serial_bitmap(Config) ->
    Pub = ?config(pub_key, Config),
    {0, _} = gen_krl_spec(Config, 7, ["-s", ?config(pub_key_file, Config)], [
        "serial: 23\nserial: 42\n"
    ]),
    #{
        krl_version := 7,
        sections := [
            {certificates, #{
                ca_key := Pub, sections := [{serial_bitmap, #{offset := 23, bitmap := <<8, 0, 1>>}}]
            }}
        ]
    } = dec_krl(Config).

dec_cert_key_id(Config) ->
    Pub = ?config(pub_key, Config),
    {0, _} = gen_krl_spec(Config, 8, ["-s", ?config(pub_key_file, Config)], ["id: foo@bar\n"]),
    #{
        krl_version := 8,
        sections := [{certificates, #{ca_key := Pub, sections := [{key_id, [<<"foo@bar">>]}]}}]
    } = dec_krl(Config).

extensions(Config) ->
    E1 = #{
        extension_name => <<"the-name">>,
        is_critical => false,
        extension_contents => <<>>
    },
    E2 = #{
        extension_name => <<"something-else">>,
        is_critical => true,
        extension_contents => <<5>>
    },
    M = #{
        krl_version => 77,
        generated_date => os:system_time(second),
        flags => 0,
        reserved => <<>>,
        comment => <<>>,
        sections => [
            {certificates, #{
                ca_key => undefined,
                reserved => <<>>,
                sections => [
                    {cert_extension, E1}
                ]
            }},
            {extension, E2}
        ]
    },
    enc_krl(Config, M),
    M = dec_krl(Config).

hash_pub_key(Config, H) when H == sha; H == sha256 ->
    base64:mime_decode(
        lists:nth(2, string:tokens(ssh:hostkey_fingerprint(H, ?config(pub_key, Config)), ":")), #{
            padding => false
        }
    ).

gen_krl(Config, Version, L) ->
    KRLFile = ?config(krl_file, Config),
    tst_util:spwn(["ssh-keygen", "-k", "-f", KRLFile, "-z", integer_to_list(Version) | L], []).

gen_krl_spec(Config, Version, Spec) -> gen_krl_spec(Config, Version, [], Spec).
gen_krl_spec(Config, Version, L, Spec) ->
    SpecFile = ?config(spec_file, Config),
    file:write_file(SpecFile, Spec),
    gen_krl(Config, Version, L ++ [SpecFile]).

dec_krl(Config) ->
    {ok, Bin} = file:read_file(?config(krl_file, Config)),
    essh_pkt:dec_krl(Bin).

enc_krl(Config, M) ->
    file:write_file(?config(krl_file, Config), essh_pkt:enc_krl(M)).

check_krl(Config, L) ->
    KRLFile = ?config(krl_file, Config),
    tst_util:spwn(["ssh-keygen", "-Q", "-f", KRLFile | L], []).

check_revoked(Config, CertOrKey) ->
    {1, M} = check_krl(Config, [CertOrKey]),
    [CertOrKey, _Comment, "REVOKED\n"] = string:tokens(M, " ").
