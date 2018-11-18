%% -----------------------------------------------------------------------------
%% The MIT License
%%
%% Copyright (c) 2018 Andrei Nesterov <ae.nesterov@gmail.com>
%%
%% Permission is hereby granted, free of charge, to any person obtaining a copy
%% of this software and associated documentation files (the "Software"), to
%% deal in the Software without restriction, including without limitation the
%% rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
%% sell copies of the Software, and to permit persons to whom the Software is
%% furnished to do so, subject to the following conditions:
%%
%% The above copyright notice and this permission notice shall be included in
%% all copies or substantial portions of the Software.
%%
%% THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
%% IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
%% FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
%% AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
%% LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
%% FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
%% IN THE SOFTWARE.
%% -----------------------------------------------------------------------------

-module(mqttgw).

-behaviour(auth_on_register_hook).
-behaviour(auth_on_subscribe_hook).
-behaviour(auth_on_publish_hook).

-ifdef(TEST).
-include_lib("proper/include/proper.hrl").
-include_lib("eunit/include/eunit.hrl").
-endif.

%% Plugin callbacks
-export([
    auth_on_register/5,
    auth_on_publish/6,
    auth_on_subscribe/3
]).

%% Types
-record(client_id, {
    agent_label :: binary(),
    account_id  :: binary(),
    audience    :: binary()
}).

-type client_id() :: #client_id{}.

%% =============================================================================
%% Plugin callbacks
%% =============================================================================

auth_on_register(
    _Peer, {_MountPoint, ClientId} = _SubscriberId, _Username,
    _Password, _CleanSession) ->

    try validate_client_id(ClientId) of
        #client_id{agent_label=AgentLabel, account_id=AccountId, audience=Audience} ->
            error_logger:info_msg(
                "Agent connected: agent_label=~s, account_id=~s, audience=~s",
                [AgentLabel, AccountId, Audience]),
            ok
    catch
        T:R ->
            error_logger:warning_msg(
                "Agent failed to connect: invalid client_id=~p, "
                "exception_type=~p, excepton_reason=~p",
                [ClientId, T, R]),
            {error, invalid_credentials}
    end.

auth_on_publish(
    _Username, {_MountPoint, ClientId} = _SubscriberId,
    _QoS, _Topic, Payload, _IsRetain) ->

    #client_id{
        agent_label=AgentLabel,
        account_id=AccountId,
        audience=Audience} = parse_client_id(ClientId),

    try envelope(AgentLabel, AccountId, Audience, Payload) of
        Envelope ->
            {ok, [{payload, Envelope}]}
    catch
        T:R ->
            error_logger:error_msg(
                "Agent failed to publish: invalid msg=~p, "
                "exception_type=~p, excepton_reason=~p",
                [Payload, T, R]),
            {error, bad_payload}
    end.

auth_on_subscribe(
    _Username, {_MountPoint, ClientId} = _SubscriberId,
    Topics) ->

    #client_id{
        agent_label=AgentLabel,
        account_id=AccountId,
        audience=Audience} = parse_client_id(ClientId),

    error_logger:info_msg(
        "Agent subscribed: agent_label=~s, account_id=~s, audience=~s, topics=~p",
        [AgentLabel, AccountId, Audience, Topics]),

    ok.

%% =============================================================================
%% Internal functions
%% =============================================================================

-spec validate_client_id(binary()) -> client_id().
validate_client_id(Val) ->
    ClientId =
        #client_id{
            agent_label=AgentLabel,
            account_id=AccountId,
            audience=Audience} = parse_client_id(Val),
    true = is_binary(AgentLabel),
    true = uuid:is_uuid(uuid:string_to_uuid(AccountId)),
    true = is_binary(Audience),
    ClientId.

-spec parse_client_id(binary()) -> client_id().
parse_client_id(<<"v1/agents/", R/bits>>) ->
    parse_v1_agent_label(R, <<>>).

-spec parse_v1_agent_label(binary(), binary()) -> client_id().
parse_v1_agent_label(<<$:, R/bits>>, Acc) ->
    parse_v1_account_id(R, Acc);
parse_v1_agent_label(<<C, R/bits>>, Acc) ->
    parse_v1_agent_label(R, <<Acc/binary, C>>);
parse_v1_agent_label(<<>>, Acc) ->
    error({bad_agent_label_id, Acc}).

-spec parse_v1_account_id(binary(), binary()) -> client_id().
parse_v1_account_id(<<AccountId:36/binary, $@, Audience/binary>>, AgentLabel) ->
    #client_id{agent_label=AgentLabel, account_id=AccountId, audience=Audience};
parse_v1_account_id(Val, _AgentLabel) ->
    error({bad_account_id, Val}).

-spec envelope(binary(), binary(), binary(), binary()) -> jsx:json_term().
envelope(AgentLabel, AccountId, Audience, Message) ->
    jsx:encode(
        #{sub => #{agent_label => AgentLabel, account_id => AccountId, audience => Audience},
          msg => Message}).

%% =============================================================================
%% Tests
%% =============================================================================

-ifdef(TEST).

uuid_t() ->
    ?LET(Val, uuid:uuid_to_string(uuid:get_v4(), binary_standard), Val).

client_id_t() ->
    ?LET(
        {AgentLabel, AccountId, Audience},
        {agent_label(), uuid_t(), agent_label()},
        <<"v1/agents/", AgentLabel/binary, $:, AccountId/binary, $@, Audience/binary>>).

subscriber_id_t() ->
    ?LET(
        {MountPoint, ClientId},
        {string(), client_id_t()},
        {MountPoint, ClientId}).

binary_utf8_t() ->
    ?LET(Val, string(), unicode:characters_to_binary(Val, utf8, utf8)).

%% Exclude:
%% - multi-level wildcard '#' = <<35>>
%% - single-level wildcard '+' = <<43>>
%% - single-level separator '/' = <<47>>
%% - symbols: :' = <<58>>
agent_label() ->
    ?LET(
        Val,
        list(union([
            integer(0, 34),
            integer(36, 42),
            integer(44, 46),
            integer(48, 57),
            integer(59, 16#10ffff)
        ])),
        unicode:characters_to_binary(Val, utf8, utf8)).

%% Exclude:
%% - multi-level wildcard '#' = <<35>>
%% - single-level wildcard '+' = <<43>>
%% - single-level separator '/' = <<47>>
publish_topic_t() ->
    ?LET(
        Val,
        list(union([
            integer(0, 34),
            integer(36, 42),
            integer(44, 46),
            integer(48, 16#10ffff)
        ])),
        unicode:characters_to_binary(Val, utf8, utf8)).

subscribe_topic_t() ->
    ?LET(Val, binary_utf8_t(), Val).

qos_t() ->
    ?LET(Val, integer(0, 2), Val).

prop_onconnect() ->
    ?FORALL(
        {Peer, SubscriberId, Username, Password, CleanSession},
        {any(), subscriber_id_t(), binary_utf8_t(), binary_utf8_t(), boolean()},
        ok =:= auth_on_register(Peer, SubscriberId, Username, Password, CleanSession)).

prop_onconnect_invalid_credentials() ->
    ?FORALL(
        {Peer, MountPoint, ClientId, Username, Password, CleanSession},
        {any(), string(), binary(32), binary_utf8_t(), binary_utf8_t(), boolean()},
        {error, invalid_credentials} =:=
            auth_on_register(Peer, {MountPoint, ClientId}, Username, Password, CleanSession)).

prop_onpublish() ->
    ?FORALL(
        {Username, SubscriberId, QoS, Topic, Payload, IsRetain},
        {binary_utf8_t(), subscriber_id_t(),
         qos_t(), publish_topic_t(), binary_utf8_t(), boolean()},
        begin
            #client_id{
                agent_label=AgentLabel,
                account_id=AccountId,
                audience=Audience} = parse_client_id(element(2, SubscriberId)),
            {ok, Modifiers} =
                auth_on_publish(Username, SubscriberId, QoS, Topic, Payload, IsRetain),
            {_, Envelope} = lists:keyfind(payload, 1, Modifiers),
            Envelope =:= envelope(AgentLabel, AccountId, Audience, Payload)
        end).

prop_onsubscribe() ->
    ?FORALL(
        {Username, SubscriberId, Topics},
        {binary_utf8_t(), subscriber_id_t(), list({subscribe_topic_t(), qos_t()})},
        ok =:= auth_on_subscribe(Username, SubscriberId, Topics)).

-endif.
