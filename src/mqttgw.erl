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
-behaviour(auth_on_publish_hook).
-behaviour(on_deliver_hook).
-behaviour(auth_on_subscribe_hook).

-ifdef(TEST).
-include_lib("proper/include/proper.hrl").
-include_lib("eunit/include/eunit.hrl").
-endif.

%% Plugin callbacks
-export([
    auth_on_register/5,
    auth_on_publish/6,
    on_deliver/4,
    auth_on_subscribe/3
]).

%% Types
-type connection_mode() :: default | payload_only.

-record(client_id, {
    mode        :: connection_mode(),
    agent_label :: binary(),
    account_id  :: binary(),
    audience    :: binary()
}).
-type client_id() :: #client_id{}.

-record (envelope, {
    payload    :: binary(),
    properties :: map()
}).
-type envelope() :: #envelope{}.

%% =============================================================================
%% Plugin callbacks
%% =============================================================================

auth_on_register(
    _Peer, {_MountPoint, ClientId} = _SubscriberId, _Username,
    _Password, _CleanSession) ->

    try validate_client_id(parse_client_id(ClientId)) of
        #client_id{
            mode=Mode,
            agent_label=AgentLabel,
            account_id=AccountId,
            audience=Audience} ->
            error_logger:info_msg(
                "Agent connected: mode=~p, agent_label=~s, account_id=~s, audience=~s",
                [Mode, AgentLabel, AccountId, Audience]),
            ok
    catch
        T:R ->
            error_logger:warning_msg(
                "Agent failed to connect: invalid client_id=~p, "
                "exception_type=~p, exception_reason=~p",
                [ClientId, T, R]),
            {error, invalid_credentials}
    end.

auth_on_publish(
    _Username, {_MountPoint, ClientId} = _SubscriberId,
    _QoS, _Topic, Payload, _IsRetain) ->

    #client_id{
        mode=Mode,
        agent_label=AgentLabel,
        account_id=AccountId,
        audience=Audience} = parse_client_id(ClientId),

    try envelope(
            AgentLabel, AccountId, Audience,
            validate_envelope(parse_envelope(Mode, Payload))) of
        UpdatedPayload ->
            {ok, [{payload, UpdatedPayload}]}
    catch
        T:R ->
            error_logger:error_msg(
                "Agent failed to publish: invalid msg=~p, "
                "exception_type=~p, exception_reason=~p",
                [Payload, T, R]),
            {error, bad_payload}
    end.

on_deliver(
    _Username, {_MountPoint, ClientId} = _SubscriberId,
    _Topic, Payload) ->

    #client_id{mode=Mode} = parse_client_id(ClientId),

    try deliver_envelope(Mode, Payload) of
        UpdatedPayload ->
            {ok, [{payload, UpdatedPayload}]}
    catch
        T:R ->
            error_logger:error_msg(
                "Agent failed to publish: invalid msg=~p, "
                "exception_type=~p, exception_reason=~p",
                [Payload, T, R]),
            {error, bad_payload}
    end.

auth_on_subscribe(
    _Username, {_MountPoint, ClientId} = _SubscriberId,
    Topics) ->

    #client_id{
        mode=Mode,
        agent_label=AgentLabel,
        account_id=AccountId,
        audience=Audience} = parse_client_id(ClientId),

    error_logger:info_msg(
        "Agent subscribed: mode=~p, agent_label=~s, account_id=~s, audience=~s, topics=~p",
        [Mode, AgentLabel, AccountId, Audience, Topics]),

    ok.

%% =============================================================================
%% Internal functions
%% =============================================================================

-spec validate_client_id(client_id()) -> client_id().
validate_client_id(Val) ->
    #client_id{
        agent_label=AgentLabel,
        account_id=AccountId,
        audience=Audience} = Val,

    true = is_binary(AgentLabel),
    true = uuid:is_uuid(uuid:string_to_uuid(AccountId)),
    true = is_binary(Audience),
    Val.

-spec parse_client_id(binary()) -> client_id().
parse_client_id(<<"v1.mqtt3/agents/", R/bits>>) ->
    parse_v1_agent_label(R, default, <<>>);
parse_client_id(<<"v1.mqtt3.payload-only/agents/", R/bits>>) ->
    parse_v1_agent_label(R, payload_only, <<>>).

-spec parse_v1_agent_label(binary(), connection_mode(), binary()) -> client_id().
parse_v1_agent_label(<<$., R/bits>>, Mode, Acc) ->
    parse_v1_account_id(R, Mode, Acc);
parse_v1_agent_label(<<C, R/bits>>, Mode, Acc) ->
    parse_v1_agent_label(R, Mode, <<Acc/binary, C>>);
parse_v1_agent_label(<<>>, _Mode, Acc) ->
    error({bad_agent_label_id, Acc}).

-spec parse_v1_account_id(binary(), connection_mode(), binary()) -> client_id().
parse_v1_account_id(<<AccountId:36/binary, $., Audience/binary>>, Mode, AgentLabel) ->
    #client_id{agent_label=AgentLabel, account_id=AccountId, audience=Audience, mode=Mode};
parse_v1_account_id(Val, _Mode, _AgentLabel) ->
    error({bad_account_id, Val}).

-spec validate_envelope(envelope()) -> envelope().
validate_envelope(Val) ->
    #envelope{
        payload=Payload,
        properties=Properties} = Val,

    true = is_binary(Payload),
    true = is_map(Properties),
    Val.

-spec parse_envelope(connection_mode(), binary()) -> envelope().
parse_envelope(default, Message) ->
    Envelope = jsx:decode(Message, [return_maps]),
    Payload = maps:get(<<"payload">>, Envelope),
    Properties = maps:get(<<"properties">>, Envelope, #{}),
    #envelope{payload=Payload, properties=Properties};
parse_envelope(payload_only, Message) ->
    #envelope{payload=Message, properties=#{}}.

-spec envelope(binary(), binary(), binary(), envelope()) -> binary().
envelope(AgentLabel, AccountId, Audience, Envelope) ->
    #envelope{
        payload=Payload,
        properties=Properties} = Envelope,

    %% Override authn properties
    UpdatedProperties =
        Properties#{
            <<"agent_label">> => AgentLabel,
            <<"account_id">> => AccountId,
            <<"audience">> => Audience},

    jsx:encode(
        #{properties => UpdatedProperties,
          payload => Payload}).

-spec deliver_envelope(connection_mode(), binary()) -> binary().
deliver_envelope(Mode, Payload) ->
    Envelope = validate_envelope(parse_envelope(default, Payload)),
    case Mode of
        default ->
            Payload;
        payload_only ->
            #envelope{payload=InnerPayload} = Envelope,
            InnerPayload
    end.

%% =============================================================================
%% Tests
%% =============================================================================

-ifdef(TEST).

uuid_t() ->
    ?LET(Val, uuid:uuid_to_string(uuid:get_v4(), binary_standard), Val).

version_t() ->
    ?LET(
        Index,
        choose(1, 2),
        lists:nth(Index, [<<"v1.mqtt3">>, <<"v1.mqtt3.payload-only">>])).

client_id_t() ->
    ?LET(
        {Version, AgentLabel, AccountId, Audience},
        {version_t(), agent_label_t(), uuid_t(), agent_label_t()},
        <<Version/binary,
          "/agents/", AgentLabel/binary, $., AccountId/binary, $., Audience/binary>>).

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
%% - symbols: '.' = <<46>>
agent_label_t() ->
    ?LET(
        Val,
        list(union([
            integer(0, 34),
            integer(36, 42),
            integer(44, 45),
            integer(48, 16#10ffff)
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
                mode=Mode,
                agent_label=AgentLabel,
                account_id=AccountId,
                audience=Audience} = parse_client_id(element(2, SubscriberId)),
            ExpectedProperties =
                #{<<"agent_label">> => AgentLabel,
                  <<"account_id">> => AccountId,
                  <<"audience">> => Audience},
            ExpectedMessage = jsx:encode(#{payload => Payload, properties => ExpectedProperties}),
            InputMessage =
                case Mode of
                    default      -> jsx:encode(#{payload => Payload});
                    payload_only -> Payload
                end,

            {ok, Modifiers} =
                auth_on_publish(Username, SubscriberId, QoS, Topic, InputMessage, IsRetain),
            {_, OutputMessage} = lists:keyfind(payload, 1, Modifiers),
            OutputMessage =:= ExpectedMessage
        end).

prop_ondeliver() ->
    ?FORALL(
        {Username, SubscriberId, Topic, Payload},
        {binary_utf8_t(), subscriber_id_t(),
         publish_topic_t(), binary_utf8_t()},
        begin
            #client_id{
                mode=Mode,
                agent_label=AgentLabel,
                account_id=AccountId,
                audience=Audience} = parse_client_id(element(2, SubscriberId)),
            ExpectedProperties =
                #{<<"agent_label">> => AgentLabel,
                  <<"account_id">> => AccountId,
                  <<"audience">> => Audience},
            InputMessage = jsx:encode(#{payload => Payload, properties => ExpectedProperties}),
            ExpectedMessage =
                case Mode of
                    default      -> InputMessage;
                    payload_only -> Payload
                end,

            {ok, Modifiers} =
                on_deliver(Username, SubscriberId, Topic, InputMessage),
            {_, OutputMessage} = lists:keyfind(payload, 1, Modifiers),
            OutputMessage =:= ExpectedMessage
        end).

prop_onsubscribe() ->
    ?FORALL(
        {Username, SubscriberId, Topics},
        {binary_utf8_t(), subscriber_id_t(), list({subscribe_topic_t(), qos_t()})},
        ok =:= auth_on_subscribe(Username, SubscriberId, Topics)).

-endif.
