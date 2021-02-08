-module(bankid).

-export([endpoint/1,
         auth/3,
         auth/4,
         sign/5,
         sign/6,
         collect/2,
         cancel/2
        ]).

-export_type([endpoint/0,
              option/0,
              options/0,
              end_user_ip/0,
              personal_number/0,
              requirements/0,
              requirement/0,
              user_visible_data/0,
              user_non_visible_data/0,
              order/0,
              order_ref/0,
              auto_start_token/0,
              qr_start_token/0,
              qr_start_secret/0,
              auth_response/0,
              sign_response/0,
              collect_response/0,
              completion_data/0,
              user/0,
              name/0,
              givenName/0,
              surname/0,
              device/0,
              ip_address/0,
              cert/0,
              unix_ms_string/0,
              signature/0,
              ocsp_response/0,
              pending_hint_code/0,
              failed_hint_code/0,
              error_details/0,
              client_error/0,
              request_error/0
             ]).

-define(ENDPOINT_TEST, "https://appapi2.test.bankid.com/rp/v5.1").
-define(ENDPOINT_PRODUCTION, "https://appapi2.bankid.com/rp/v5.1").
-define(SSL_CACERTFILE, "./priv/ssl/BankIDCA_test.cert.pem").
-define(MAX_RETRIES, 10).
-define(TIMEOUT, 5000).

-opaque endpoint() :: httpc:url().
-type option() :: {endpoint, endpoint()} |
                  {cacertfile, ssl:client_cafile()} |
                  {certfile, ssl:cert_pem()} |
                  {keyfile, ssl:key_pem()} |
                  {password, ssl:key_password()} |
                  {max_retries, integer()} |
                  {timeout, integer()}.
-type options() :: list(option()).
-type end_user_ip() :: inet:ip4_address().
-type personal_number() :: binary().
-type requirements() :: {cardReader, class1 | class2} |
                        {certificatePolicies, binary()} |
                        {issuerCn, binary()} |
                        {autoStartTokenRequired, boolean()} | % deprecated
                        {allowFingerprint, boolean()} |
                        {tokenStartRequired, boolean()}.
-type requirement() :: list(requirements()).
-type user_visible_data() :: binary() | {markdown, binary()}.
-type user_non_visible_data() :: binary().
-type order() :: list({orderRef, order_ref()} |
                      {autoStartToken, auto_start_token()} |
                      {qrStartToken, qr_start_token()} |
                      {qrStartSecret, qr_start_secret()}).
-type order_ref() :: binary().
-type auto_start_token() :: binary().
-type qr_start_token() :: binary().
-type qr_start_secret() :: binary().
-type auth_response() :: order().
-type sign_response() :: order().
-type collect_response() :: {complete, completion_data()} |
                            {pending, pending_hint_code()} |
                            {failed, failed_hint_code()}.
-type completion_data() :: list({user, user()} |
                                {device, device()} |
                                {cert, cert()} |
                                {signature, signature()} |
                                {ocspResponse, ocsp_response()}).
-type user() :: list({personalNumber, personal_number()} |
                     {name, name()} |
                     {givenName, givenName()} |
                     {surname, surname()}).
-type name() :: binary().
-type givenName() :: binary().
-type surname() :: binary().
-type device() :: [{ipAddress, ip_address()}].
-type ip_address() :: binary().
-type cert() :: list({notBefore, unix_ms_string()} |
                     {notAfter, unix_ms_string()}).
-type unix_ms_string() :: binary().
-type signature() :: binary().
-type ocsp_response() :: binary().
-type pending_hint_code() :: outstandingTransaction | noClient | started | userSign | binary().
-type failed_hint_code() :: expiredTransaction | certificateErr | userCancel | cancelled | startFailed | binary().
-type error_details() :: binary().
-type client_error() :: {alreadyInProgress, error_details()} |
                        {invalidParameters, error_details()} |
                        {error, binary(), error_details()}.
-type request_error() :: client_error() | internal | timeout | maintenance.

-spec endpoint(production | test) -> endpoint().
endpoint(production) ->
    ?ENDPOINT_PRODUCTION;
endpoint(test) ->
    ?ENDPOINT_TEST.

-spec auth(end_user_ip(), personal_number(), options()) -> {ok, auth_response()} | {error, request_error()};
          (end_user_ip(), requirement(), options()) -> {ok, auth_response()} | {error, request_error()}.
-spec auth(end_user_ip(), personal_number(), requirement(), options()) -> {ok, auth_response()} | {error, request_error()}.
auth(EndUserIp, Requirement, Options) when is_list(Requirement) ->
    auth([{endUserIp, normalize_ip(EndUserIp)},
          {requirement, Requirement}
         ], Options);
auth(EndUserIp, PersonalNumber, Options) ->
    auth([{endUserIp, normalize_ip(EndUserIp)},
          {personalNumber, normalize_pnr(PersonalNumber)}
         ], Options).
auth(EndUserIp, PersonalNumber, Requirement, Options) ->
    auth([{endUserIp, normalize_ip(EndUserIp)},
          {personalNumber, normalize_pnr(PersonalNumber)},
          {requirement, Requirement}
         ], Options).
auth(Parameters, Options) when is_list(Parameters) ->
    case post("auth", Parameters, Options) of
        {200,_Headers,Body} ->
            {ok, order_ref(Body)};
        Response ->
            {error, handle_error(Response)}
    end.

-spec sign(end_user_ip(), personal_number(), user_visible_data(), user_non_visible_data(), options()) -> {ok, sign_response()} | {error, request_error()}.
-spec sign(end_user_ip(), personal_number(), user_visible_data(), user_non_visible_data(), requirement(), options()) -> {ok, sign_response()} | {error, request_error()}.
sign(EndUserIp, PersonalNumber, {markdown, UserVisibleData}, UserNonVisibleData, Options) ->
    sign([{endUserIp, normalize_ip(EndUserIp)},
          {personalNumber, normalize_pnr(PersonalNumber)},
          {userVisibleData, encode_data(UserVisibleData)},
          {userNonVisibleData, encode_data(UserNonVisibleData)},
          {userVisibleDataFormat, <<"simpleMarkdownV1">>}
         ], Options);
sign(EndUserIp, PersonalNumber, UserVisibleData, UserNonVisibleData, Options) ->
    sign([{endUserIp, normalize_ip(EndUserIp)},
          {personalNumber, normalize_pnr(PersonalNumber)},
          {userVisibleData, encode_data(UserVisibleData)},
          {userNonVisibleData, encode_data(UserNonVisibleData)}
         ], Options).
sign(EndUserIp, PersonalNumber, {markdown,UserVisibleData}, UserNonVisibleData, Requirement, Options) ->
    sign([{endUserIp, normalize_ip(EndUserIp)},
          {personalNumber, normalize_pnr(PersonalNumber)},
          {requirement, Requirement},
          {userVisibleData, encode_data(UserVisibleData)},
          {userNonVisibleData, encode_data(UserNonVisibleData)},
          {userVisibleDataFormat, <<"simpleMarkdownV1">>}
         ], Options);
sign(EndUserIp, PersonalNumber, UserVisibleData, UserNonVisibleData, Requirement, Options) ->
    sign([{endUserIp, normalize_ip(EndUserIp)},
          {personalNumber, normalize_pnr(PersonalNumber)},
          {requirement, Requirement},
          {userVisibleData, encode_data(UserVisibleData)},
          {userNonVisibleData, encode_data(UserNonVisibleData)}
         ], Options).
sign(Parameters, Options) ->
    case post("sign", Parameters, Options) of
        {200,_Headers,Body} ->
            {ok, order_ref(Body)};
        Response ->
            {error, handle_error(Response)}
    end.

-spec collect(order_ref(), options()) -> {ok, collect_response()} | {error, request_error()}.
collect(OrderRef, Options) ->
    collect(OrderRef, 0, Options).
collect(OrderRef, Retries, Options) ->
    MaxRetries = proplists:get_value(max_retries, Options, ?MAX_RETRIES),
    case post("collect", [{orderRef, OrderRef}], Options) of
        {200,_Headers,Body} ->
            {ok, handle_collect(Body)};
        {503,_Headers,_Body} when Retries < MaxRetries ->
            collect(OrderRef, Retries+1, Options);
        Response ->
            {error, handle_error(Response)}
    end.

-spec cancel(order_ref(), options()) -> ok | {error, request_error()}.
cancel(OrderRef, Options) ->
    case post("cancel", [{orderRef, OrderRef}], Options) of
        {200,_Headers,_Body} -> ok;
        Response -> {error, handle_error(Response)}
    end.

%%%%%%%%%%%%%%
%% INTERNAL %%
%%%%%%%%%%%%%%

post(Cmd, Body, Options) ->
    Endpoint = proplists:get_value(endpoint, Options, ?ENDPOINT_PRODUCTION),
    logger:debug(#{uri => request_uri(Endpoint,Cmd),
                   body => jsx:encode(Body),
                   options => Options
                  }),
    {ok,{{_,Status,_},ResponseHeaders,ResponseBody}} =
        httpc:request(post, {request_uri(Endpoint,Cmd), [], "application/json", jsx:encode(Body)},
                    [{timeout, proplists:get_value(timeout, Options, ?TIMEOUT)},
                     {ssl, [{versions, ['tlsv1.2']},
                            {cacertfile, proplists:get_value(cacertfile, Options, ?SSL_CACERTFILE)},
                            {certfile, proplists:get_value(certfile, Options)},
                            {keyfile, proplists:get_value(keyfile, Options)},
                            {password, proplists:get_value(password, Options)}
                           ]}
                    ], []),
    case proplists:get_value("content-type",ResponseHeaders) of
        "application/json" ->
            {Status,ResponseHeaders,jsx:decode(list_to_binary(ResponseBody))};
        _ ->
            {Status,ResponseHeaders,ResponseBody}
    end.

request_uri(Endpoint, Resource) ->
    io_lib:format("~s/~s", [Endpoint, Resource]).

normalize_ip(Ip) ->
    list_to_binary(inet:ntoa(Ip)).

normalize_pnr(Pnr) ->
    binary:replace(binary:replace(Pnr, <<"-">>, <<"">>), <<"+">>, <<"">>).

encode_data(Data) ->
    base64:encode(Data).

order_ref(#{<<"orderRef">>:=OrderRef,
            <<"autoStartToken">>:=AutoStartToken,
            <<"qrStartToken">>:=QrStartToken,
            <<"qrStartSecret">>:=QrStartSecret
           }) ->
    [{orderRef, OrderRef},
     {autoStartToken, AutoStartToken},
     {qrStartToken, QrStartToken},
     {qrStartSecret, QrStartSecret}
    ].

completion_data(#{<<"user">>:=User,
                  <<"device">>:=Device,
                  <<"cert">>:=Cert
                 }) ->
    [{user, User},
     {device, Device},
     {cert, Cert}
    ];
completion_data(#{<<"user">>:=User,
                  <<"device">>:=Device,
                  <<"cert">>:=Cert,
                  <<"signature">>:=Signature,
                  <<"ocspResponse">>:=OcspResponse
                 }) ->
    [{user, user(User)},
     {device, device(Device)},
     {cert, cert(Cert)},
     {signature, Signature},
     {ocspResponse, OcspResponse}
    ].

user(#{<<"personalNumber">>:=PersonalNumber,
       <<"name">>:=Name,
       <<"givenName">>:=GivenName,
       <<"surname">>:=Surname
      }) ->
    [{personalNumber, PersonalNumber},
     {name, Name},
     {givenName, GivenName},
     {surname, Surname}
    ].

device(#{<<"ipAddress">>:=IpAddress}) ->
    [{ipAddress, IpAddress}].

cert(#{<<"notBefore">>:=NotBefore,
       <<"notAfter">>:=NotAfter
      }) ->
    [{notBefore, NotBefore},
     {notAfter, NotAfter}
    ].

handle_collect(#{<<"status">>:=<<"complete">>, <<"completionData">>:=CompletionData}) ->
    {complete, completion_data(CompletionData)};
handle_collect(#{<<"status">>:=<<"pending">>, <<"hintCode">>:=HintCode}) ->
    case HintCode of
        <<"outstandingTransaction">> -> {pending, outstandingTransaction};
        <<"noClient">> -> {pending, noClient};
        <<"started">> -> {pending, started};
        <<"userSign">> -> {pending, userSign};
        _ -> {pending, HintCode}
    end;
handle_collect(#{<<"status">>:=<<"failed">>, <<"hintCode">>:=HintCode}) ->
    case HintCode of
        <<"expiredTransaction">> -> {failed, expiredTransaction};
        <<"certificateErr">> -> {failed, certificateErr};
        <<"userCancel">> -> {failed, userCancel};
        <<"cancelled">> -> {failed, cancelled};
        <<"startFailed">> -> {failed, startFailed};
        _ -> {failed, HintCode}
    end.

handle_error({400,_Headers,#{<<"errorCode">>:=ErrorCode,<<"details">>:=Details}}) ->
    case ErrorCode of
        <<"alreadyInProgress">> -> {alreadyInProgress, Details};
        <<"invalidParameters">> -> {invalidParameters, Details};
        _ -> {ErrorCode, Details}
    end;
handle_error({408,_Headers,Body}) ->
    logger:notice(Body),
    timeout;
handle_error({500,_Headers,Body}) ->
    logger:notice(Body),
    internal;
handle_error({503,_Headers,Body}) ->
    logger:notice(Body),
    maintenance.

