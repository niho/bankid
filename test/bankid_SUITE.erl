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
    [{bankid_rp, [sequence], [auth_test, sign_test, sign_markdown_test, cancel_test]}].

init_per_suite(Config) ->
    DataDir = ?config(data_dir, Config),
    Options = [{environment, test},
               {cacertfile, filename:join(DataDir, ?SSL_CACERTFILE)},
               {certfile, filename:join(DataDir, ?SSL_CERTFILE)},
               {keyfile, filename:join(DataDir, ?SSL_KEYFILE)},
               {password, ?SSL_PASSWORD}
              ],
    [{bankid_options,Options},
     {bankid_pnr, list_to_binary(os:getenv("BANKID_PNR", "1212121212"))}
    ] ++ Config.

end_per_suite(Config) ->
    Config.

auth_test(Config) ->
    Options = ?config(bankid_options, Config),
    PersonalNumber = ?config(bankid_pnr, Config),
    {ok,OrderRef} = bankid:auth({0,0,0,0}, PersonalNumber, Options),
    {ok,_CompletionData} = collect(OrderRef, Options),
    ok.

sign_test(Config) ->
    Options = ?config(bankid_options, Config),
    PersonalNumber = ?config(bankid_pnr, Config),
    {ok,OrderRef} = bankid:sign({0,0,0,0}, PersonalNumber, <<"Test">>, <<"TestData">>, Options),
    {ok,_CompletionData} = collect(OrderRef, Options),
    ok.

sign_markdown_test(Config) ->
    Options = ?config(bankid_options, Config),
    PersonalNumber = ?config(bankid_pnr, Config),
    {ok,OrderRef} = bankid:sign({0,0,0,0}, PersonalNumber, {markdown, <<"# Test\n\nHello **world**.">>}, <<"TestData">>, Options),
    {ok,_CompletionData} = collect(OrderRef, Options),
    ok.

cancel_test(Config) ->
    Options = ?config(bankid_options, Config),
    PersonalNumber = ?config(bankid_pnr, Config),
    {ok,OrderRef} = bankid:auth({0,0,0,0}, PersonalNumber, Options),
    ok = bankid:cancel(proplists:get_value(orderRef, OrderRef), Options),
    ok.

collect(OrderRef, Options) ->
    case bankid:collect(proplists:get_value(orderRef, OrderRef), Options) of
        {ok, {complete, CompletionData}} -> {ok, CompletionData};
        {ok, {pending, _}} -> collect(OrderRef, Options);
        {ok, {failed, Failure}} -> {error, Failure}
    end.

