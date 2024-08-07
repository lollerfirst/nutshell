"""
@generated by mypy-protobuf.  Do not edit manually!
isort:skip_file
"""

import abc
import collections.abc
import typing

import grpc
import grpc.aio

import cashu.lightning.lnd_grpc.protos.lightning_pb2
import cashu.lightning.lnd_grpc.protos.router_pb2

_T = typing.TypeVar("_T")

class _MaybeAsyncIterator(collections.abc.AsyncIterator[_T], collections.abc.Iterator[_T], metaclass=abc.ABCMeta): ...

class _ServicerContext(grpc.ServicerContext, grpc.aio.ServicerContext):  # type: ignore[misc, type-arg]
    ...

class RouterStub:
    """
    Comments in this file will be directly parsed into the API
    Documentation as descriptions of the associated method, message, or field.
    These descriptions should go right above the definition of the object, and
    can be in either block or // comment format.

    An RPC method can be matched to an lncli command by placing a line in the
    beginning of the description in exactly the following format:
    lncli: `methodname`

    Failure to specify the exact name of the command will cause documentation
    generation to fail.

    More information on how exactly the gRPC documentation is generated from
    this proto file can be found here:
    https://github.com/lightninglabs/lightning-api

    Router is a service that offers advanced interaction with the router
    subsystem of the daemon.
    """

    def __init__(self, channel: typing.Union[grpc.Channel, grpc.aio.Channel]) -> None: ...
    SendPaymentV2: grpc.UnaryStreamMultiCallable[
        cashu.lightning.lnd_grpc.protos.router_pb2.SendPaymentRequest,
        cashu.lightning.lnd_grpc.protos.lightning_pb2.Payment,
    ]
    """
    SendPaymentV2 attempts to route a payment described by the passed
    PaymentRequest to the final destination. The call returns a stream of
    payment updates. When using this RPC, make sure to set a fee limit, as the
    default routing fee limit is 0 sats. Without a non-zero fee limit only
    routes without fees will be attempted which often fails with
    FAILURE_REASON_NO_ROUTE.
    """

    TrackPaymentV2: grpc.UnaryStreamMultiCallable[
        cashu.lightning.lnd_grpc.protos.router_pb2.TrackPaymentRequest,
        cashu.lightning.lnd_grpc.protos.lightning_pb2.Payment,
    ]
    """lncli: `trackpayment`
    TrackPaymentV2 returns an update stream for the payment identified by the
    payment hash.
    """

    TrackPayments: grpc.UnaryStreamMultiCallable[
        cashu.lightning.lnd_grpc.protos.router_pb2.TrackPaymentsRequest,
        cashu.lightning.lnd_grpc.protos.lightning_pb2.Payment,
    ]
    """
    TrackPayments returns an update stream for every payment that is not in a
    terminal state. Note that if payments are in-flight while starting a new
    subscription, the start of the payment stream could produce out-of-order
    and/or duplicate events. In order to get updates for every in-flight
    payment attempt make sure to subscribe to this method before initiating any
    payments.
    """

    EstimateRouteFee: grpc.UnaryUnaryMultiCallable[
        cashu.lightning.lnd_grpc.protos.router_pb2.RouteFeeRequest,
        cashu.lightning.lnd_grpc.protos.router_pb2.RouteFeeResponse,
    ]
    """
    EstimateRouteFee allows callers to obtain a lower bound w.r.t how much it
    may cost to send an HTLC to the target end destination.
    """

    SendToRoute: grpc.UnaryUnaryMultiCallable[
        cashu.lightning.lnd_grpc.protos.router_pb2.SendToRouteRequest,
        cashu.lightning.lnd_grpc.protos.router_pb2.SendToRouteResponse,
    ]
    """
    Deprecated, use SendToRouteV2. SendToRoute attempts to make a payment via
    the specified route. This method differs from SendPayment in that it
    allows users to specify a full route manually. This can be used for
    things like rebalancing, and atomic swaps. It differs from the newer
    SendToRouteV2 in that it doesn't return the full HTLC information.
    """

    SendToRouteV2: grpc.UnaryUnaryMultiCallable[
        cashu.lightning.lnd_grpc.protos.router_pb2.SendToRouteRequest,
        cashu.lightning.lnd_grpc.protos.lightning_pb2.HTLCAttempt,
    ]
    """
    SendToRouteV2 attempts to make a payment via the specified route. This
    method differs from SendPayment in that it allows users to specify a full
    route manually. This can be used for things like rebalancing, and atomic
    swaps.
    """

    ResetMissionControl: grpc.UnaryUnaryMultiCallable[
        cashu.lightning.lnd_grpc.protos.router_pb2.ResetMissionControlRequest,
        cashu.lightning.lnd_grpc.protos.router_pb2.ResetMissionControlResponse,
    ]
    """lncli: `resetmc`
    ResetMissionControl clears all mission control state and starts with a clean
    slate.
    """

    QueryMissionControl: grpc.UnaryUnaryMultiCallable[
        cashu.lightning.lnd_grpc.protos.router_pb2.QueryMissionControlRequest,
        cashu.lightning.lnd_grpc.protos.router_pb2.QueryMissionControlResponse,
    ]
    """lncli: `querymc`
    QueryMissionControl exposes the internal mission control state to callers.
    It is a development feature.
    """

    XImportMissionControl: grpc.UnaryUnaryMultiCallable[
        cashu.lightning.lnd_grpc.protos.router_pb2.XImportMissionControlRequest,
        cashu.lightning.lnd_grpc.protos.router_pb2.XImportMissionControlResponse,
    ]
    """lncli: `importmc`
    XImportMissionControl is an experimental API that imports the state provided
    to the internal mission control's state, using all results which are more
    recent than our existing values. These values will only be imported
    in-memory, and will not be persisted across restarts.
    """

    GetMissionControlConfig: grpc.UnaryUnaryMultiCallable[
        cashu.lightning.lnd_grpc.protos.router_pb2.GetMissionControlConfigRequest,
        cashu.lightning.lnd_grpc.protos.router_pb2.GetMissionControlConfigResponse,
    ]
    """lncli: `getmccfg`
    GetMissionControlConfig returns mission control's current config.
    """

    SetMissionControlConfig: grpc.UnaryUnaryMultiCallable[
        cashu.lightning.lnd_grpc.protos.router_pb2.SetMissionControlConfigRequest,
        cashu.lightning.lnd_grpc.protos.router_pb2.SetMissionControlConfigResponse,
    ]
    """lncli: `setmccfg`
    SetMissionControlConfig will set mission control's config, if the config
    provided is valid.
    """

    QueryProbability: grpc.UnaryUnaryMultiCallable[
        cashu.lightning.lnd_grpc.protos.router_pb2.QueryProbabilityRequest,
        cashu.lightning.lnd_grpc.protos.router_pb2.QueryProbabilityResponse,
    ]
    """lncli: `queryprob`
    Deprecated. QueryProbability returns the current success probability
    estimate for a given node pair and amount. The call returns a zero success
    probability if no channel is available or if the amount violates min/max
    HTLC constraints.
    """

    BuildRoute: grpc.UnaryUnaryMultiCallable[
        cashu.lightning.lnd_grpc.protos.router_pb2.BuildRouteRequest,
        cashu.lightning.lnd_grpc.protos.router_pb2.BuildRouteResponse,
    ]
    """lncli: `buildroute`
    BuildRoute builds a fully specified route based on a list of hop public
    keys. It retrieves the relevant channel policies from the graph in order to
    calculate the correct fees and time locks.
    Note that LND will use its default final_cltv_delta if no value is supplied.
    Make sure to add the correct final_cltv_delta depending on the invoice
    restriction. Moreover the caller has to make sure to provide the
    payment_addr if the route is paying an invoice which signaled it.
    """

    SubscribeHtlcEvents: grpc.UnaryStreamMultiCallable[
        cashu.lightning.lnd_grpc.protos.router_pb2.SubscribeHtlcEventsRequest,
        cashu.lightning.lnd_grpc.protos.router_pb2.HtlcEvent,
    ]
    """
    SubscribeHtlcEvents creates a uni-directional stream from the server to
    the client which delivers a stream of htlc events.
    """

    SendPayment: grpc.UnaryStreamMultiCallable[
        cashu.lightning.lnd_grpc.protos.router_pb2.SendPaymentRequest,
        cashu.lightning.lnd_grpc.protos.router_pb2.PaymentStatus,
    ]
    """
    Deprecated, use SendPaymentV2. SendPayment attempts to route a payment
    described by the passed PaymentRequest to the final destination. The call
    returns a stream of payment status updates.
    """

    TrackPayment: grpc.UnaryStreamMultiCallable[
        cashu.lightning.lnd_grpc.protos.router_pb2.TrackPaymentRequest,
        cashu.lightning.lnd_grpc.protos.router_pb2.PaymentStatus,
    ]
    """
    Deprecated, use TrackPaymentV2. TrackPayment returns an update stream for
    the payment identified by the payment hash.
    """

    HtlcInterceptor: grpc.StreamStreamMultiCallable[
        cashu.lightning.lnd_grpc.protos.router_pb2.ForwardHtlcInterceptResponse,
        cashu.lightning.lnd_grpc.protos.router_pb2.ForwardHtlcInterceptRequest,
    ]
    """*
    HtlcInterceptor dispatches a bi-directional streaming RPC in which
    Forwarded HTLC requests are sent to the client and the client responds with
    a boolean that tells LND if this htlc should be intercepted.
    In case of interception, the htlc can be either settled, cancelled or
    resumed later by using the ResolveHoldForward endpoint.
    """

    UpdateChanStatus: grpc.UnaryUnaryMultiCallable[
        cashu.lightning.lnd_grpc.protos.router_pb2.UpdateChanStatusRequest,
        cashu.lightning.lnd_grpc.protos.router_pb2.UpdateChanStatusResponse,
    ]
    """lncli: `updatechanstatus`
    UpdateChanStatus attempts to manually set the state of a channel
    (enabled, disabled, or auto). A manual "disable" request will cause the
    channel to stay disabled until a subsequent manual request of either
    "enable" or "auto".
    """

class RouterAsyncStub:
    """
    Comments in this file will be directly parsed into the API
    Documentation as descriptions of the associated method, message, or field.
    These descriptions should go right above the definition of the object, and
    can be in either block or // comment format.

    An RPC method can be matched to an lncli command by placing a line in the
    beginning of the description in exactly the following format:
    lncli: `methodname`

    Failure to specify the exact name of the command will cause documentation
    generation to fail.

    More information on how exactly the gRPC documentation is generated from
    this proto file can be found here:
    https://github.com/lightninglabs/lightning-api

    Router is a service that offers advanced interaction with the router
    subsystem of the daemon.
    """

    SendPaymentV2: grpc.aio.UnaryStreamMultiCallable[
        cashu.lightning.lnd_grpc.protos.router_pb2.SendPaymentRequest,
        cashu.lightning.lnd_grpc.protos.lightning_pb2.Payment,
    ]
    """
    SendPaymentV2 attempts to route a payment described by the passed
    PaymentRequest to the final destination. The call returns a stream of
    payment updates. When using this RPC, make sure to set a fee limit, as the
    default routing fee limit is 0 sats. Without a non-zero fee limit only
    routes without fees will be attempted which often fails with
    FAILURE_REASON_NO_ROUTE.
    """

    TrackPaymentV2: grpc.aio.UnaryStreamMultiCallable[
        cashu.lightning.lnd_grpc.protos.router_pb2.TrackPaymentRequest,
        cashu.lightning.lnd_grpc.protos.lightning_pb2.Payment,
    ]
    """lncli: `trackpayment`
    TrackPaymentV2 returns an update stream for the payment identified by the
    payment hash.
    """

    TrackPayments: grpc.aio.UnaryStreamMultiCallable[
        cashu.lightning.lnd_grpc.protos.router_pb2.TrackPaymentsRequest,
        cashu.lightning.lnd_grpc.protos.lightning_pb2.Payment,
    ]
    """
    TrackPayments returns an update stream for every payment that is not in a
    terminal state. Note that if payments are in-flight while starting a new
    subscription, the start of the payment stream could produce out-of-order
    and/or duplicate events. In order to get updates for every in-flight
    payment attempt make sure to subscribe to this method before initiating any
    payments.
    """

    EstimateRouteFee: grpc.aio.UnaryUnaryMultiCallable[
        cashu.lightning.lnd_grpc.protos.router_pb2.RouteFeeRequest,
        cashu.lightning.lnd_grpc.protos.router_pb2.RouteFeeResponse,
    ]
    """
    EstimateRouteFee allows callers to obtain a lower bound w.r.t how much it
    may cost to send an HTLC to the target end destination.
    """

    SendToRoute: grpc.aio.UnaryUnaryMultiCallable[
        cashu.lightning.lnd_grpc.protos.router_pb2.SendToRouteRequest,
        cashu.lightning.lnd_grpc.protos.router_pb2.SendToRouteResponse,
    ]
    """
    Deprecated, use SendToRouteV2. SendToRoute attempts to make a payment via
    the specified route. This method differs from SendPayment in that it
    allows users to specify a full route manually. This can be used for
    things like rebalancing, and atomic swaps. It differs from the newer
    SendToRouteV2 in that it doesn't return the full HTLC information.
    """

    SendToRouteV2: grpc.aio.UnaryUnaryMultiCallable[
        cashu.lightning.lnd_grpc.protos.router_pb2.SendToRouteRequest,
        cashu.lightning.lnd_grpc.protos.lightning_pb2.HTLCAttempt,
    ]
    """
    SendToRouteV2 attempts to make a payment via the specified route. This
    method differs from SendPayment in that it allows users to specify a full
    route manually. This can be used for things like rebalancing, and atomic
    swaps.
    """

    ResetMissionControl: grpc.aio.UnaryUnaryMultiCallable[
        cashu.lightning.lnd_grpc.protos.router_pb2.ResetMissionControlRequest,
        cashu.lightning.lnd_grpc.protos.router_pb2.ResetMissionControlResponse,
    ]
    """lncli: `resetmc`
    ResetMissionControl clears all mission control state and starts with a clean
    slate.
    """

    QueryMissionControl: grpc.aio.UnaryUnaryMultiCallable[
        cashu.lightning.lnd_grpc.protos.router_pb2.QueryMissionControlRequest,
        cashu.lightning.lnd_grpc.protos.router_pb2.QueryMissionControlResponse,
    ]
    """lncli: `querymc`
    QueryMissionControl exposes the internal mission control state to callers.
    It is a development feature.
    """

    XImportMissionControl: grpc.aio.UnaryUnaryMultiCallable[
        cashu.lightning.lnd_grpc.protos.router_pb2.XImportMissionControlRequest,
        cashu.lightning.lnd_grpc.protos.router_pb2.XImportMissionControlResponse,
    ]
    """lncli: `importmc`
    XImportMissionControl is an experimental API that imports the state provided
    to the internal mission control's state, using all results which are more
    recent than our existing values. These values will only be imported
    in-memory, and will not be persisted across restarts.
    """

    GetMissionControlConfig: grpc.aio.UnaryUnaryMultiCallable[
        cashu.lightning.lnd_grpc.protos.router_pb2.GetMissionControlConfigRequest,
        cashu.lightning.lnd_grpc.protos.router_pb2.GetMissionControlConfigResponse,
    ]
    """lncli: `getmccfg`
    GetMissionControlConfig returns mission control's current config.
    """

    SetMissionControlConfig: grpc.aio.UnaryUnaryMultiCallable[
        cashu.lightning.lnd_grpc.protos.router_pb2.SetMissionControlConfigRequest,
        cashu.lightning.lnd_grpc.protos.router_pb2.SetMissionControlConfigResponse,
    ]
    """lncli: `setmccfg`
    SetMissionControlConfig will set mission control's config, if the config
    provided is valid.
    """

    QueryProbability: grpc.aio.UnaryUnaryMultiCallable[
        cashu.lightning.lnd_grpc.protos.router_pb2.QueryProbabilityRequest,
        cashu.lightning.lnd_grpc.protos.router_pb2.QueryProbabilityResponse,
    ]
    """lncli: `queryprob`
    Deprecated. QueryProbability returns the current success probability
    estimate for a given node pair and amount. The call returns a zero success
    probability if no channel is available or if the amount violates min/max
    HTLC constraints.
    """

    BuildRoute: grpc.aio.UnaryUnaryMultiCallable[
        cashu.lightning.lnd_grpc.protos.router_pb2.BuildRouteRequest,
        cashu.lightning.lnd_grpc.protos.router_pb2.BuildRouteResponse,
    ]
    """lncli: `buildroute`
    BuildRoute builds a fully specified route based on a list of hop public
    keys. It retrieves the relevant channel policies from the graph in order to
    calculate the correct fees and time locks.
    Note that LND will use its default final_cltv_delta if no value is supplied.
    Make sure to add the correct final_cltv_delta depending on the invoice
    restriction. Moreover the caller has to make sure to provide the
    payment_addr if the route is paying an invoice which signaled it.
    """

    SubscribeHtlcEvents: grpc.aio.UnaryStreamMultiCallable[
        cashu.lightning.lnd_grpc.protos.router_pb2.SubscribeHtlcEventsRequest,
        cashu.lightning.lnd_grpc.protos.router_pb2.HtlcEvent,
    ]
    """
    SubscribeHtlcEvents creates a uni-directional stream from the server to
    the client which delivers a stream of htlc events.
    """

    SendPayment: grpc.aio.UnaryStreamMultiCallable[
        cashu.lightning.lnd_grpc.protos.router_pb2.SendPaymentRequest,
        cashu.lightning.lnd_grpc.protos.router_pb2.PaymentStatus,
    ]
    """
    Deprecated, use SendPaymentV2. SendPayment attempts to route a payment
    described by the passed PaymentRequest to the final destination. The call
    returns a stream of payment status updates.
    """

    TrackPayment: grpc.aio.UnaryStreamMultiCallable[
        cashu.lightning.lnd_grpc.protos.router_pb2.TrackPaymentRequest,
        cashu.lightning.lnd_grpc.protos.router_pb2.PaymentStatus,
    ]
    """
    Deprecated, use TrackPaymentV2. TrackPayment returns an update stream for
    the payment identified by the payment hash.
    """

    HtlcInterceptor: grpc.aio.StreamStreamMultiCallable[
        cashu.lightning.lnd_grpc.protos.router_pb2.ForwardHtlcInterceptResponse,
        cashu.lightning.lnd_grpc.protos.router_pb2.ForwardHtlcInterceptRequest,
    ]
    """*
    HtlcInterceptor dispatches a bi-directional streaming RPC in which
    Forwarded HTLC requests are sent to the client and the client responds with
    a boolean that tells LND if this htlc should be intercepted.
    In case of interception, the htlc can be either settled, cancelled or
    resumed later by using the ResolveHoldForward endpoint.
    """

    UpdateChanStatus: grpc.aio.UnaryUnaryMultiCallable[
        cashu.lightning.lnd_grpc.protos.router_pb2.UpdateChanStatusRequest,
        cashu.lightning.lnd_grpc.protos.router_pb2.UpdateChanStatusResponse,
    ]
    """lncli: `updatechanstatus`
    UpdateChanStatus attempts to manually set the state of a channel
    (enabled, disabled, or auto). A manual "disable" request will cause the
    channel to stay disabled until a subsequent manual request of either
    "enable" or "auto".
    """

class RouterServicer(metaclass=abc.ABCMeta):
    """
    Comments in this file will be directly parsed into the API
    Documentation as descriptions of the associated method, message, or field.
    These descriptions should go right above the definition of the object, and
    can be in either block or // comment format.

    An RPC method can be matched to an lncli command by placing a line in the
    beginning of the description in exactly the following format:
    lncli: `methodname`

    Failure to specify the exact name of the command will cause documentation
    generation to fail.

    More information on how exactly the gRPC documentation is generated from
    this proto file can be found here:
    https://github.com/lightninglabs/lightning-api

    Router is a service that offers advanced interaction with the router
    subsystem of the daemon.
    """

    @abc.abstractmethod
    def SendPaymentV2(
        self,
        request: cashu.lightning.lnd_grpc.protos.router_pb2.SendPaymentRequest,
        context: _ServicerContext,
    ) -> typing.Union[collections.abc.Iterator[cashu.lightning.lnd_grpc.protos.lightning_pb2.Payment], collections.abc.AsyncIterator[cashu.lightning.lnd_grpc.protos.lightning_pb2.Payment]]:
        """
        SendPaymentV2 attempts to route a payment described by the passed
        PaymentRequest to the final destination. The call returns a stream of
        payment updates. When using this RPC, make sure to set a fee limit, as the
        default routing fee limit is 0 sats. Without a non-zero fee limit only
        routes without fees will be attempted which often fails with
        FAILURE_REASON_NO_ROUTE.
        """

    @abc.abstractmethod
    def TrackPaymentV2(
        self,
        request: cashu.lightning.lnd_grpc.protos.router_pb2.TrackPaymentRequest,
        context: _ServicerContext,
    ) -> typing.Union[collections.abc.Iterator[cashu.lightning.lnd_grpc.protos.lightning_pb2.Payment], collections.abc.AsyncIterator[cashu.lightning.lnd_grpc.protos.lightning_pb2.Payment]]:
        """lncli: `trackpayment`
        TrackPaymentV2 returns an update stream for the payment identified by the
        payment hash.
        """

    @abc.abstractmethod
    def TrackPayments(
        self,
        request: cashu.lightning.lnd_grpc.protos.router_pb2.TrackPaymentsRequest,
        context: _ServicerContext,
    ) -> typing.Union[collections.abc.Iterator[cashu.lightning.lnd_grpc.protos.lightning_pb2.Payment], collections.abc.AsyncIterator[cashu.lightning.lnd_grpc.protos.lightning_pb2.Payment]]:
        """
        TrackPayments returns an update stream for every payment that is not in a
        terminal state. Note that if payments are in-flight while starting a new
        subscription, the start of the payment stream could produce out-of-order
        and/or duplicate events. In order to get updates for every in-flight
        payment attempt make sure to subscribe to this method before initiating any
        payments.
        """

    @abc.abstractmethod
    def EstimateRouteFee(
        self,
        request: cashu.lightning.lnd_grpc.protos.router_pb2.RouteFeeRequest,
        context: _ServicerContext,
    ) -> typing.Union[cashu.lightning.lnd_grpc.protos.router_pb2.RouteFeeResponse, collections.abc.Awaitable[cashu.lightning.lnd_grpc.protos.router_pb2.RouteFeeResponse]]:
        """
        EstimateRouteFee allows callers to obtain a lower bound w.r.t how much it
        may cost to send an HTLC to the target end destination.
        """

    @abc.abstractmethod
    def SendToRoute(
        self,
        request: cashu.lightning.lnd_grpc.protos.router_pb2.SendToRouteRequest,
        context: _ServicerContext,
    ) -> typing.Union[cashu.lightning.lnd_grpc.protos.router_pb2.SendToRouteResponse, collections.abc.Awaitable[cashu.lightning.lnd_grpc.protos.router_pb2.SendToRouteResponse]]:
        """
        Deprecated, use SendToRouteV2. SendToRoute attempts to make a payment via
        the specified route. This method differs from SendPayment in that it
        allows users to specify a full route manually. This can be used for
        things like rebalancing, and atomic swaps. It differs from the newer
        SendToRouteV2 in that it doesn't return the full HTLC information.
        """

    @abc.abstractmethod
    def SendToRouteV2(
        self,
        request: cashu.lightning.lnd_grpc.protos.router_pb2.SendToRouteRequest,
        context: _ServicerContext,
    ) -> typing.Union[cashu.lightning.lnd_grpc.protos.lightning_pb2.HTLCAttempt, collections.abc.Awaitable[cashu.lightning.lnd_grpc.protos.lightning_pb2.HTLCAttempt]]:
        """
        SendToRouteV2 attempts to make a payment via the specified route. This
        method differs from SendPayment in that it allows users to specify a full
        route manually. This can be used for things like rebalancing, and atomic
        swaps.
        """

    @abc.abstractmethod
    def ResetMissionControl(
        self,
        request: cashu.lightning.lnd_grpc.protos.router_pb2.ResetMissionControlRequest,
        context: _ServicerContext,
    ) -> typing.Union[cashu.lightning.lnd_grpc.protos.router_pb2.ResetMissionControlResponse, collections.abc.Awaitable[cashu.lightning.lnd_grpc.protos.router_pb2.ResetMissionControlResponse]]:
        """lncli: `resetmc`
        ResetMissionControl clears all mission control state and starts with a clean
        slate.
        """

    @abc.abstractmethod
    def QueryMissionControl(
        self,
        request: cashu.lightning.lnd_grpc.protos.router_pb2.QueryMissionControlRequest,
        context: _ServicerContext,
    ) -> typing.Union[cashu.lightning.lnd_grpc.protos.router_pb2.QueryMissionControlResponse, collections.abc.Awaitable[cashu.lightning.lnd_grpc.protos.router_pb2.QueryMissionControlResponse]]:
        """lncli: `querymc`
        QueryMissionControl exposes the internal mission control state to callers.
        It is a development feature.
        """

    @abc.abstractmethod
    def XImportMissionControl(
        self,
        request: cashu.lightning.lnd_grpc.protos.router_pb2.XImportMissionControlRequest,
        context: _ServicerContext,
    ) -> typing.Union[cashu.lightning.lnd_grpc.protos.router_pb2.XImportMissionControlResponse, collections.abc.Awaitable[cashu.lightning.lnd_grpc.protos.router_pb2.XImportMissionControlResponse]]:
        """lncli: `importmc`
        XImportMissionControl is an experimental API that imports the state provided
        to the internal mission control's state, using all results which are more
        recent than our existing values. These values will only be imported
        in-memory, and will not be persisted across restarts.
        """

    @abc.abstractmethod
    def GetMissionControlConfig(
        self,
        request: cashu.lightning.lnd_grpc.protos.router_pb2.GetMissionControlConfigRequest,
        context: _ServicerContext,
    ) -> typing.Union[cashu.lightning.lnd_grpc.protos.router_pb2.GetMissionControlConfigResponse, collections.abc.Awaitable[cashu.lightning.lnd_grpc.protos.router_pb2.GetMissionControlConfigResponse]]:
        """lncli: `getmccfg`
        GetMissionControlConfig returns mission control's current config.
        """

    @abc.abstractmethod
    def SetMissionControlConfig(
        self,
        request: cashu.lightning.lnd_grpc.protos.router_pb2.SetMissionControlConfigRequest,
        context: _ServicerContext,
    ) -> typing.Union[cashu.lightning.lnd_grpc.protos.router_pb2.SetMissionControlConfigResponse, collections.abc.Awaitable[cashu.lightning.lnd_grpc.protos.router_pb2.SetMissionControlConfigResponse]]:
        """lncli: `setmccfg`
        SetMissionControlConfig will set mission control's config, if the config
        provided is valid.
        """

    @abc.abstractmethod
    def QueryProbability(
        self,
        request: cashu.lightning.lnd_grpc.protos.router_pb2.QueryProbabilityRequest,
        context: _ServicerContext,
    ) -> typing.Union[cashu.lightning.lnd_grpc.protos.router_pb2.QueryProbabilityResponse, collections.abc.Awaitable[cashu.lightning.lnd_grpc.protos.router_pb2.QueryProbabilityResponse]]:
        """lncli: `queryprob`
        Deprecated. QueryProbability returns the current success probability
        estimate for a given node pair and amount. The call returns a zero success
        probability if no channel is available or if the amount violates min/max
        HTLC constraints.
        """

    @abc.abstractmethod
    def BuildRoute(
        self,
        request: cashu.lightning.lnd_grpc.protos.router_pb2.BuildRouteRequest,
        context: _ServicerContext,
    ) -> typing.Union[cashu.lightning.lnd_grpc.protos.router_pb2.BuildRouteResponse, collections.abc.Awaitable[cashu.lightning.lnd_grpc.protos.router_pb2.BuildRouteResponse]]:
        """lncli: `buildroute`
        BuildRoute builds a fully specified route based on a list of hop public
        keys. It retrieves the relevant channel policies from the graph in order to
        calculate the correct fees and time locks.
        Note that LND will use its default final_cltv_delta if no value is supplied.
        Make sure to add the correct final_cltv_delta depending on the invoice
        restriction. Moreover the caller has to make sure to provide the
        payment_addr if the route is paying an invoice which signaled it.
        """

    @abc.abstractmethod
    def SubscribeHtlcEvents(
        self,
        request: cashu.lightning.lnd_grpc.protos.router_pb2.SubscribeHtlcEventsRequest,
        context: _ServicerContext,
    ) -> typing.Union[collections.abc.Iterator[cashu.lightning.lnd_grpc.protos.router_pb2.HtlcEvent], collections.abc.AsyncIterator[cashu.lightning.lnd_grpc.protos.router_pb2.HtlcEvent]]:
        """
        SubscribeHtlcEvents creates a uni-directional stream from the server to
        the client which delivers a stream of htlc events.
        """

    @abc.abstractmethod
    def SendPayment(
        self,
        request: cashu.lightning.lnd_grpc.protos.router_pb2.SendPaymentRequest,
        context: _ServicerContext,
    ) -> typing.Union[collections.abc.Iterator[cashu.lightning.lnd_grpc.protos.router_pb2.PaymentStatus], collections.abc.AsyncIterator[cashu.lightning.lnd_grpc.protos.router_pb2.PaymentStatus]]:
        """
        Deprecated, use SendPaymentV2. SendPayment attempts to route a payment
        described by the passed PaymentRequest to the final destination. The call
        returns a stream of payment status updates.
        """

    @abc.abstractmethod
    def TrackPayment(
        self,
        request: cashu.lightning.lnd_grpc.protos.router_pb2.TrackPaymentRequest,
        context: _ServicerContext,
    ) -> typing.Union[collections.abc.Iterator[cashu.lightning.lnd_grpc.protos.router_pb2.PaymentStatus], collections.abc.AsyncIterator[cashu.lightning.lnd_grpc.protos.router_pb2.PaymentStatus]]:
        """
        Deprecated, use TrackPaymentV2. TrackPayment returns an update stream for
        the payment identified by the payment hash.
        """

    @abc.abstractmethod
    def HtlcInterceptor(
        self,
        request_iterator: _MaybeAsyncIterator[cashu.lightning.lnd_grpc.protos.router_pb2.ForwardHtlcInterceptResponse],
        context: _ServicerContext,
    ) -> typing.Union[collections.abc.Iterator[cashu.lightning.lnd_grpc.protos.router_pb2.ForwardHtlcInterceptRequest], collections.abc.AsyncIterator[cashu.lightning.lnd_grpc.protos.router_pb2.ForwardHtlcInterceptRequest]]:
        """*
        HtlcInterceptor dispatches a bi-directional streaming RPC in which
        Forwarded HTLC requests are sent to the client and the client responds with
        a boolean that tells LND if this htlc should be intercepted.
        In case of interception, the htlc can be either settled, cancelled or
        resumed later by using the ResolveHoldForward endpoint.
        """

    @abc.abstractmethod
    def UpdateChanStatus(
        self,
        request: cashu.lightning.lnd_grpc.protos.router_pb2.UpdateChanStatusRequest,
        context: _ServicerContext,
    ) -> typing.Union[cashu.lightning.lnd_grpc.protos.router_pb2.UpdateChanStatusResponse, collections.abc.Awaitable[cashu.lightning.lnd_grpc.protos.router_pb2.UpdateChanStatusResponse]]:
        """lncli: `updatechanstatus`
        UpdateChanStatus attempts to manually set the state of a channel
        (enabled, disabled, or auto). A manual "disable" request will cause the
        channel to stay disabled until a subsequent manual request of either
        "enable" or "auto".
        """

def add_RouterServicer_to_server(servicer: RouterServicer, server: typing.Union[grpc.Server, grpc.aio.Server]) -> None: ...
