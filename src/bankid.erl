% @author Niklas Holmgren <niklas.holmgren@gmail.com>
% @copyright 2021 Niklas Holmgren
% @doc BankID Relaying Party v5.1 API.
%
% This module implements a client for the BankID Relaying Party API.
% The Relaying Party (RP) is the server side proxy between the BankID service and
% the end user client (typically the BankID mobile app). The client in this module
% is stateless and works by creating an auth or sign order. The order status can then
% be collected on a regular interval (typically every 1-2 seconds) until it either
% completes or fails. See the official BankID documentation for a more in-depth
% description of how the flow works.
%
% == Client options ==
% To use the client with the production environment you need to specify the location
% of your SSL certificate and private key (in PEM format) as obtained from your bank.
% Certificates For the test environment is included with the library and does not
% need to be specified in the client options.
%
% ```
% auth(IpAddress, [
%   {environment, production},
%   {certfile, "./priv/BankIDFP_prod.crt.pem"},
%   {keyfile, "./priv/BankIDFP_prod.key.pem"},
%   {password, "qwerty123"}
% ]).
% '''
%
% == PEM files ==
%
% You can use OpenSSL to convert the SSL certificate you obtain from your bank to
% the PEM format required by this library.
%
% Make sure you encrypt and password protect the generated PEM files by specifying
% the -aes256 parameter (encrypt with AES256). 
%
% == End user IP address ==
%
% Calls to auth and sign require you to specify the IP address of the end user.
% Note the importance of using the correct IP address. It must be the IP
% address representing the user agent (the end user device) as seen by the RP.
% If there is a proxy for inbound traffic, special considerations may need to
% be taken to get the correct address. In some use cases the IP address is not
% available, for instance for voice based services. In this case, the internal
% representation of those systems IP address is ok to use.
%
-module(bankid).

-export([auth/2,
         auth/3,
         auth/4,
         sign/4,
         sign/5,
         sign/6,
         collect/2,
         cancel/2
        ]).

-export_type([endpoint_url/0,
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

-define(DEFAULT_ENVIRONMENT, test).
-define(ENDPOINT_TEST, "https://appapi2.test.bankid.com/rp/v5.1").
-define(ENDPOINT_PRODUCTION, "https://appapi2.bankid.com/rp/v5.1").
-define(SSL_CACERTFILE, filename:join(code:priv_dir(bankid), "ssl/BankIDCA_test.cert.pem")).
-define(SSL_CERTFILE, filename:join(code:priv_dir(bankid), "ssl/BankIDFP_test.crt.pem")).
-define(SSL_KEYFILE, filename:join(code:priv_dir(bankid), "ssl/BankIDFP_test.key.pem")).
-define(SSL_PASSWORD, "qwerty123").
-define(MAX_RETRIES, 10).
-define(TIMEOUT, 5000).

%%%%%%%%%%%
%% TYPES %%
%%%%%%%%%%%

-type environment() :: production | test.
-type endpoint_url() :: httpc:url().
-type option() :: {environment, environment()} |
                  {endpoint, endpoint_url()} |
                  {cacertfile, ssl:client_cafile()} |
                  {certfile, ssl:cert_pem()} |
                  {keyfile, ssl:key_pem()} |
                  {password, ssl:key_password()} |
                  {max_retries, integer()} |
                  {timeout, integer()}.
-type options() :: list(option()).
-type end_user_ip() :: inet:ip_address().
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

%%%%%%%%%
%% API %%
%%%%%%%%%

% @doc Initiate an authentication order.
%
% When the personal number is excluded, the client must be started
% with the autoStartToken returned in the response.
%
% Use the collect method to query the status of the order. If the request is
% successful the response includes orderRef, autoStartToken, qrStartToken
% and qrStartSecret.
%
% @param EndUserIp The user IP address as seen by RP. IPv4 and IPv6 is allowed.
% @param Options Client options.
%
% @see auth/3
% @see auth/4
%
% @equiv auth(EndUserIp, null, [{}], Options)
%
-spec auth(end_user_ip(), options()) -> {ok, auth_response()} | {error, request_error()}.
auth(EndUserIp, Options) ->
    auth({[{endUserIp, normalize_ip(EndUserIp)}], Options}).

% @doc Initiate an authentication order with a personal number.
%
% Use the collect method to query the status of the order. If the request is
% successful the response includes orderRef, autoStartToken, qrStartToken
% and qrStartSecret.
%
% @param EndUserIp The user IP address as seen by RP. IPv4 and IPv6 is allowed.
% @param PersonalNumber The personal number of the user. 12 digits. Century
% must be included.
% @param Options Client options.
%
% @see auth/2
% @see auth/4
%
% @equiv auth(EndUserIp, PersonalNumber, [{}], Options)
%
-spec auth(end_user_ip(), personal_number(), options()) -> {ok, auth_response()} | {error, request_error()}.
auth(EndUserIp, PersonalNumber, Options) ->
    auth({[{endUserIp, normalize_ip(EndUserIp)},
           {personalNumber, normalize_pnr(PersonalNumber)}
          ], Options}).

% @doc Initiate an authentication order with a personal number and requirements.
%
% Use the collect method to query the status of the order. If the request is
% successful the response includes orderRef, autoStartToken, qrStartToken
% and qrStartSecret.
%
% RP may use the requirement parameter to describe how the signature must be
% created and verified. A typical use case is to require Mobile BankID or a
% special card reader.
%
% @param EndUserIp The user IP address as seen by RP. IPv4 and IPv6 is allowed.
% @param PersonalNumber The personal number of the user. 12 digits. Century
% must be included.
% @param Requirement Requirements on how the auth order must be performed.
% @param Options Client options.
%
% @see auth/2
% @see auth/3
%
-spec auth(end_user_ip(), personal_number(), requirement(), options()) -> {ok, auth_response()} | {error, request_error()}.
auth(EndUserIp, PersonalNumber, Requirement, Options) ->
    auth({[{endUserIp, normalize_ip(EndUserIp)},
           {personalNumber, normalize_pnr(PersonalNumber)},
           {requirement, Requirement}
          ], Options}).

% @private
auth({Parameters, Options}) ->
    case post("auth", Parameters, Options) of
        {200,_Headers,Body} ->
            {ok, order_ref(Body)};
        Response ->
            {error, handle_error(Response)}
    end.

% @doc Initiates a signing order with a personal number.
%
% When the personal number is excluded, the client must be started
% with the autoStartToken returned in the response.
%
% Use the collect method to query the status of the order. If the request is
% successful the response includes orderRef, autoStartToken, qrStartToken
% and qrStartSecret.
%
% @param EndUserIp The user IP address as seen by RP. IPv4 and IPv6 is allowed.
% @param UserVisibleData The text to be displayed and signed.
% @param UserNonVisibleData Data not displayed to the user.
% @param Options Client options.
%
% @see sign/5
% @see sign/6
%
% @equiv sign(EndUserIp, null, UserVisibleData, UserNonVisibleData, [{}], Options)
%
-spec sign(end_user_ip(), user_visible_data(), user_non_visible_data(), options()) -> {ok, sign_response()} | {error, request_error()}.
sign(EndUserIp, UserVisibleData, UserNonVisibleData, Options) ->
    sign(EndUserIp, null, UserVisibleData, UserNonVisibleData, [{}], Options).

% @doc Initiates a signing order with a personal number.
%
% Use the collect method to query the status of the order. If the request is
% successful the response includes orderRef, autoStartToken, qrStartToken
% and qrStartSecret.
%
% @param EndUserIp The user IP address as seen by RP. IPv4 and IPv6 is allowed.
% @param PersonalNumber The personal number of the user. 12 digits. Century
% must be included.
% @param UserVisibleData The text to be displayed and signed.
% @param UserNonVisibleData Data not displayed to the user.
% @param Options Client options.
%
% @see sign/4
% @see sign/6
%
% @equiv sign(EndUserIp, PersonalNumber, UserVisibleData, UserNonVisibleData, [{}], Options)
%
-spec sign(end_user_ip(), personal_number(), user_visible_data(), user_non_visible_data(), options()) -> {ok, sign_response()} | {error, request_error()}.
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

% @doc Initiates a signing order with a personal number and requirements.
%
% Use the collect method to query the status of the order. If the request is
% successful the response includes orderRef, autoStartToken, qrStartToken
% and qrStartSecret.
%
% RP may use the requirement parameter to describe how the signature must be
% created and verified. A typical use case is to require Mobile BankID or a
% special card reader.
%
% @param EndUserIp The user IP address as seen by RP. IPv4 and IPv6 is allowed.
% @param PersonalNumber The personal number of the user. 12 digits. Century
% must be included.
% @param UserVisibleData The text to be displayed and signed.
% @param UserNonVisibleData Data not displayed to the user.
% @param Requirement Requirements on how the sign order must be performed.
% @param Options Client options.
%
% @see sign/4
% @see sign/5
%
-spec sign(end_user_ip(), personal_number(), user_visible_data(), user_non_visible_data(), requirement(), options()) -> {ok, sign_response()} | {error, request_error()}.
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

% @private
sign(Parameters, Options) ->
    case post("sign", Parameters, Options) of
        {200,_Headers,Body} ->
            {ok, order_ref(Body)};
        Response ->
            {error, handle_error(Response)}
    end.

% @doc Collects the result of a sign or auth order using the orderRef as reference.
%
% RP should keep on calling collect every two seconds as long as status indicates
% pending. RP must abort if status indicates failed. The user identity is returned
% when complete.
%
% The response will have different content depending on status of the order.
% The status may be pending, failed or complete.
%
% @param OrderRef The orderRef returned from auth or sign.
% @param Options Client options.
%
-spec collect(order_ref(), options()) -> {ok, collect_response()} | {error, request_error()}.
collect(OrderRef, Options) ->
    collect(OrderRef, 0, Options).

% @private
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

% @doc Cancels an ongoing sign or auth order.
%
% This is typically used if the user cancels the order in your service or app.
%
% @param OrderRef The orderRef returned from auth or sign.
% @param Options Client options.
%
-spec cancel(order_ref(), options()) -> ok | {error, request_error()}.
cancel(OrderRef, Options) ->
    case post("cancel", [{orderRef, OrderRef}], Options) of
        {200,_Headers,_Body} -> ok;
        Response -> {error, handle_error(Response)}
    end.

%%%%%%%%%%%%%%
%% INTERNAL %%
%%%%%%%%%%%%%%

endpoint(production) ->
    ?ENDPOINT_PRODUCTION;
endpoint(test) ->
    ?ENDPOINT_TEST.

post(Cmd, Body, Options) ->
    Env = proplists:get_value(environment, Options, ?DEFAULT_ENVIRONMENT),
    Endpoint = proplists:get_value(endpoint, Options, endpoint(Env)),
    logger:debug(#{uri => request_uri(Endpoint, Cmd),
                   body => jsx:encode(Body),
                   options => Options
                  }),
    {ok,{{_,Status,_},ResponseHeaders,ResponseBody}} =
        httpc:request(post, {request_uri(Endpoint,Cmd), [], "application/json", jsx:encode(Body)},
                    [{timeout, proplists:get_value(timeout, Options, ?TIMEOUT)},
                     {ssl, [{versions, ['tlsv1.2']},
                            {cacertfile, proplists:get_value(cacertfile, Options, ?SSL_CACERTFILE)},
                            {certfile, proplists:get_value(certfile, Options, ?SSL_CERTFILE)},
                            {keyfile, proplists:get_value(keyfile, Options, ?SSL_KEYFILE)},
                            {password, proplists:get_value(password, Options, ?SSL_PASSWORD)}
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

