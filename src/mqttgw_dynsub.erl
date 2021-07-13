-module(mqttgw_dynsub).

%% API
-export([
    read_config/0,
    list/1
]).

%% Types
-type subject() :: mqttgw:connection().
-type object()  :: [binary()].
-type data()    :: #{app := binary(), object := object(), version := binary()}.

-export_types([subject/0, object/0, data/0]).

%% =============================================================================
%% API
%% =============================================================================

-spec read_config() -> disabled | enabled.
read_config() ->
    case os:getenv("APP_DYNSUB_ENABLED", "1") of
        "0" ->
            error_logger:info_msg("[CONFIG] Dynamic subscriptions are disabled~n"),
            disabled;
        _ ->
            enabled
    end.

-spec list(subject()) -> [data()].
list(Subject) ->
    filter(vmq_subscriber_db:read({"", Subject})).

%% =============================================================================
%% Internal functions
%% =============================================================================

filter(undefined) ->
    [];
filter(L) ->
    lists:flatmap(fun({_, _, S}) ->
        lists:foldl(
            fun
                ({[<<"apps">>, App, <<"api">>, Ver | Object] = Topic, _Qos}, Acc) ->
                    Data =
                        #{app => App,
                          object => Object,
                          version => Ver,
                          topic => Topic},
                    [Data | Acc];
                ({[<<"broadcasts">>, App, <<"api">>, Ver | Object] = Topic, _Qos}, Acc) ->
                    Data =
                        #{app => App,
                          object => Object,
                          version => Ver,
                          topic => Topic},
                    [Data | Acc];
                (_, Acc) ->
                    Acc
            end,
            [], S)
        end,
        L).
