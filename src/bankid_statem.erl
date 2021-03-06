% @author Niklas Holmgren <niklas.holmgren@gmail.com>
% @copyright 2021 Niklas Holmgren
% @doc BankID State Machine.
%
% A simple state machine that implements the BankID flow. Do not use
% this in a production system. This module is only useful for very
% simple cases like testing and development.
%
% ```
% {ok,Pid} = bankid_statem:start_link({self(), ClientOpts}).
% {ok,_Order} = bankid_statem:auth(Pid, IpAddr, PersonalNumber, [{}]).
% receive
%   {bankid, {complete, _CompletionData}} -> ok;
%   {bankid, {failed, _Failure}} -> error
% end.
% '''
%
-module(bankid_statem).

-behaviour(gen_statem).

-export([start/1,
         start_link/1,
         init/1,
         callback_mode/0,
         handle_event/4,
         code_change/4,
         terminate/3,
         auth/4,
         sign/6,
         cancel/1
        ]).

-define(TIMEOUT, 1000). % milliseconds

-record(data, {pid, options}).

%% ==================================================================
%% gen_statem
%% ==================================================================

start(Args) ->
    gen_statem:start(?MODULE, Args, []).

start_link(Args) ->
    gen_statem:start_link(?MODULE, Args, []).

init({Pid,ClientOpt}) ->
    {ok, pending, #data{pid=Pid, options=ClientOpt}}.

callback_mode() ->
    [handle_event_function, state_enter].

code_change(_OldVsn, State, Data, _Extra) ->
    {ok, State, Data}.

terminate(normal, _State, {complete,CompletionData}) ->
    logger:notice(CompletionData),
    ok;
terminate(normal, _State, {failed,Failure}) ->
    logger:warning(Failure),
    ok;
terminate(_Reason, _State, _Data) ->
    ok.

% state callbacks

handle_event({call,From}, {auth, {EndUserIp, PersonalNumber, Requirement}}, pending, Data=#data{options=Options}) ->
    {ok, Order} = bankid:auth(EndUserIp, PersonalNumber, Requirement, Options),
    {next_state, pending, Data, [{reply, From, {ok,Order}},
                                 {{timeout,collect}, ?TIMEOUT, Order}
                                ]};
handle_event({call,From}, {sign, {EndUserIp, PersonalNumber, UserVisibleData, UserNonVisibleData, Requirement}}, pending, Data=#data{options=Options}) ->
    {ok, Order} = bankid:sign(EndUserIp, PersonalNumber, UserVisibleData, UserNonVisibleData, Requirement, Options),
    {next_state, pending, Data, [{reply, From, {ok,Order}},
                                 {{timeout,collect}, ?TIMEOUT, Order}
                                ]};
handle_event({call,From}, cancel, {pending,Order}, Data=#data{options=Options}) ->
    ok = bankid:cancel(proplists:get_value(orderRef, Order), Options),
    {next_state, canceled, Data, [{{timeout,collect}, infinity, Order},
                                  {reply, From, ok}
                                 ]};
handle_event({timeout,collect}, Order, _State, Data) ->
    {next_state, {pending,Order}, Data, [{next_event, internal, collect}]};
handle_event(internal, collect, {pending,Order}, Data=#data{options=Options}) ->
    case bankid:collect(proplists:get_value(orderRef, Order), Options) of
        {ok, {complete, CompletionData}} -> {next_state, {complete, CompletionData}, Data};
        {ok, {pending, _}} -> {next_state, {pending,Order}, Data, [{{timeout,collect}, ?TIMEOUT, Order}]};
        {ok, {failed, Failure}} -> {next_state, {failed, Failure}, Data}
    end;
handle_event(enter, _OldState, {complete,CompletionData}, #data{pid=Pid}) ->
    Pid ! {bankid, {complete, CompletionData}},
    {stop, normal, {complete, CompletionData}};
handle_event(enter, _OldState, {failed,Failure}, #data{pid=Pid}) ->
    Pid ! {bankid, {failed, Failure}},
    {stop, normal, {failed,Failure}};
handle_event(_,_,State,Options) ->
    {next_state,State,Options}.

%%
%% API
%%

auth(Pid, EndUserIp, PersonalNumber, Requirement) ->
    gen_statem:call(Pid, {auth, {EndUserIp, PersonalNumber, Requirement}}).

sign(Pid, EndUserIp, PersonalNumber, UserVisibleData, UserNonVisibleData, Requirement) ->
    gen_statem:call(Pid, {sign, {EndUserIp, PersonalNumber, UserVisibleData, UserNonVisibleData, Requirement}}).

cancel(Pid) ->
    gen_statem:call(Pid, cancel).

