-module(bankid_SUITE).

-compile(export_all).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-define(SSL_CACERTFILE, "BankIDCA_test.cert.pem").
-define(SSL_CERTFILE, "BankIDFP_test.crt.pem").
-define(SSL_KEYFILE, "BankIDFP_test.key.pem").
-define(SSL_PASSWORD, "qwerty123").

suite() ->
    [{timetrap,{seconds,30}}].

all() ->
    [{group, bankid_rp}].

groups() ->
    [{bankid_rp, [sequence], [auth_test, sign_test]}].

init_per_suite(Config) ->
    DataDir = ?config(data_dir, Config),
    Options = [{endpoint, bankid:endpoint(test)},
               {cacertfile, string:concat(DataDir, ?SSL_CACERTFILE)},
               {certfile, string:concat(DataDir, ?SSL_CERTFILE)},
               {keyfile, string:concat(DataDir, ?SSL_KEYFILE)},
               {password, ?SSL_PASSWORD}
              ],
    [{bankid_options,Options} | Config].

end_per_suite(Config) ->
    Config.

auth_test(Config) ->
    Options = ?config(bankid_options, Config),
    {ok,OrderRef} = bankid:auth({0,0,0,0}, <<"1212121212">>, Options),
    {ok,_CompletionData} = collect(OrderRef, Options),
    ok.

sign_test(Config) ->
    Options = ?config(bankid_options, Config),
    {ok,OrderRef} = bankid:sign({0,0,0,0}, <<"1212121212">>, <<"Test">>, <<"TestData">>, Options),
    {ok,_CompletionData} = collect(OrderRef, Options),
    ok.

collect(OrderRef, Options) ->
    case bankid:collect(proplists:get_value(orderRef, OrderRef), Options) of
        {ok, {complete, CompletionData}} -> {ok, CompletionData};
        {ok, {pending, _}} -> collect(OrderRef, Options);
        {ok, {failed, _Failure}} -> error
    end.

