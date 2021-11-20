import Exchange from "models/exchange";
import Request from "models/request";
import Response from "models/response";
import ExchangeListener from "models/exchange_listener";
import OAuthFlow, { FlowType } from "./oauth_flow";
import CsrfObserver from "./threat_observers/csrf_observer";
import CodePhishingObserver from "./threat_observers/authorization_code/code_phising_observer";
import CodeHistoryLeakObserver from "./threat_observers/authorization_code/code_history_leak_observer";
import TokenHistoryLeakObserver from "./threat_observers/implicit/token_leak_in_history";
import CredentialLeakageViaReferrerClientObserver from "./threat_observers/authorization_code/credential_leakage_via_referrer_client";
import { createUrl } from "../models/url";
import { UserSessionImpersonationObserver } from "./threat_observers/authorization_code/user_session_impersonation";
import { EavesDroppingAccessTokenLeakObserver } from "./threat_observers/authorization_code/eavesdropping_access_token";
import { AccessTokenLeakInTransportObserver } from "./threat_observers/implicit/token_leak_in_transport";
import { ClickJackingAttackObserver } from "./threat_observers/clickjacking_attack_observer";

export class OAuthClientAssessor implements ExchangeListener {
  private _completedFlows: OAuthFlow[] = [];
  private _activeFlow?: OAuthFlow;

  onRequest = (exchange: Exchange, request: Request) => {
    const requestInitiator = OAuthClientAssessor._getRequestInitiator(
      exchange,
      request
    );

    if (exchange.type === "main_frame") {
      const isAuthRequest = OAuthClientAssessor._isAuthorizationRequest(
        requestInitiator,
        request
      );

      if (isAuthRequest[0]) {
        const flow: OAuthFlow = {
          client: requestInitiator,
          authorizationServer: request.url.origin,
          type: isAuthRequest[1],
          observers: OAuthClientAssessor._createObservers(isAuthRequest[1]),
        };

        console.log(`Authorization request detected. Client: ${flow.client}`);
        console.log(request);

        this._activeFlow = flow;

        flow.observers.forEach((o) =>
          o.onAuthorizationRequest(exchange, request)
        );

        return;
      }

      if (OAuthClientAssessor._isRedirectUriRequest(request)) {
        const flow =
          this._activeFlow?.client == request.url.origin
            ? this._activeFlow
            : undefined;

        if (!flow) {
          //TODO: crsf attack?
          console.log("CSRF Attack detected?");
          console.log("Initiator: " + request.url.origin);
          console.log(request);
          return;
        }

        console.log(`Redirect uri request detected. Client: ${flow.client}`);
        console.log(request);

        flow.observers.forEach((o) =>
          o.onRedirectUriRequest(exchange, request)
        );

        this._activeFlow = {
          ...this._activeFlow,
          redirectUriRequestId: exchange.id,
        };

        return;
      }
    }

    if (OAuthClientAssessor._isAccessTokenRequest(request)) {
      const flow =
        this._activeFlow?.client ==
        OAuthClientAssessor._getRequestInitiator(exchange, request)
          ? this._activeFlow
          : undefined;

      if (!flow) {
        console.log("Access token request without active flow?");
        console.log("Initiator: " + request.url.origin);
        console.log(request);
        return;
      }

      flow.observers.forEach((o) => o.onTokenRequest(exchange, request));
    }

    [
      ...this._completedFlows.flatMap((f) => f.observers),
      ...(this._activeFlow?.observers || []),
    ].forEach((o) => o.onRequest(exchange, request));
  };

  onResponse = (exchange: Exchange, response: Response) => {
    if (exchange.type == "main_frame") {
      const flow = this._activeFlow;

      if (
        OAuthClientAssessor._isAuthorizationResponse(flow, exchange, response)
      ) {
        flow.observers.forEach((o) =>
          o.onAuthorizationResponse(exchange, response)
        );
      }

      if (exchange.id === flow?.redirectUriRequestId) {
        flow.observers.forEach((o) =>
          o.onRedirectUriResponse(exchange, response)
        );
        return;
      }
    }

    [
      ...this._completedFlows.flatMap((f) => f.observers),
      ...(this._activeFlow?.observers || []),
    ].forEach((o) => o.onResponse(exchange, response));
  };

  private static _getRequestInitiator(exchange: Exchange, request: Request) {
    if (exchange.requests.length === 1) return exchange.initiator;

    //Multiple requests in this exchange, there must be a redirect
    //The hostname which served this redirect might be different from the exchange's initiator

    return exchange.requests[exchange.requests.length - 2].url.origin;
  }

  private static _createObservers(flowType: FlowType) {
    if (flowType == FlowType.AuthorizationCode) {
      return [
        new CsrfObserver(),
        new ClickJackingAttackObserver(),
        new CodePhishingObserver(),
        new CodeHistoryLeakObserver(),
        new CredentialLeakageViaReferrerClientObserver(),
        new EavesDroppingAccessTokenLeakObserver(),
        new UserSessionImpersonationObserver(),
      ];
    }

    if (flowType == FlowType.Implicit) {
      return [
        new CsrfObserver(),
        new ClickJackingAttackObserver(),
        new TokenHistoryLeakObserver(),
        new AccessTokenLeakInTransportObserver(),
      ];
    }
  }

  private static readonly RESPONSE_TYPE_TO_FLOW_TYPE: Record<string, FlowType> =
    {
      code: FlowType.AuthorizationCode,
      token: FlowType.Implicit,
    };

  private static readonly AUTHORIZATION_REQUEST_MATCHERS: Record<
    string,
    (request: Request) => [boolean, FlowType]
  > = {
    "www.facebook.com": (request: Request) => [
      request.url.query.has("client_id") &&
        request.url.query.has("redirect_uri"),
      FlowType.AuthorizationCode,
    ],
  };

  private static _isAuthorizationRequest = (
    initiator: string,
    request: Request
  ): [boolean, FlowType?] => {
    if (request.method !== "GET") return [false, undefined];

    const hostname = request.url.hostname;

    if (hostname in OAuthClientAssessor.AUTHORIZATION_REQUEST_MATCHERS) {
      return OAuthClientAssessor.AUTHORIZATION_REQUEST_MATCHERS[hostname](
        request
      );
    }

    const hasParameters =
      request.url.query.has("client_id") &&
      request.url.query.has("response_type");

    if (!hasParameters) return [false, undefined];

    //TODO: Fix for github idp, validate if this assumption holds
    if (initiator == request.url.origin) {
      console.log(
        "Assuming this request is not a authorization request, initiator same as hostname"
      );
      console.log(request);

      return [false, undefined];
    }

    const responseType = request.url.query.get("response_type");

    if (!(responseType in OAuthClientAssessor.RESPONSE_TYPE_TO_FLOW_TYPE)) {
      console.log("Unknown response_type encountered, ignoring request");
      return [false, undefined];
    }

    return [true, OAuthClientAssessor.RESPONSE_TYPE_TO_FLOW_TYPE[responseType]];
  };

  private static _isAuthorizationResponse = (
    flow: OAuthFlow,
    exchange: Exchange,
    response: Response
  ): boolean => {
    //The spec shows a redirect with status code 302

    const isRedirect = Math.floor(response.statusCode / 100) == 3;

    if (!flow || !isRedirect) return false;

    const initiator =
      exchange.requests[exchange.requests.length - 1].url.origin;

    if (initiator != flow.authorizationServer) return false;

    const location = createUrl(response.headers.get("location"), initiator);

    const query = location.query;

    if (query.has("code")) {
      if (response.statusCode != 302) {
        console.log(
          "Authorization response detected with statuscode different from 302"
        );
        console.log(response);
      }

      return true;
    }

    const fragment = location.fragment;

    if (
      fragment.includes("access_token=") &&
      fragment.includes("token_type=")
    ) {
      if (response.statusCode != 302) {
        console.log(
          "Authorization response detected with statuscode different from 302"
        );
        console.log(response);
      }

      return true;
    }
  };

  private static _isRedirectUriRequest = (request: Request): boolean => {
    //TODO: detect authorization responses using POST as well
    if (request.method !== "GET") {
      return false;
    }

    const query = request.url.query;
    const fragment = request.url.fragment;

    return (
      query.has("code") ||
      (fragment.includes("access_token=") && fragment.includes("token_type="))
    );
  };

  private static _isAccessTokenRequest = (request: Request): boolean => {
    if (request.method !== "POST") {
      return false;
    }

    const formData = request.body?.formData;

    if (!formData) return false;

    const grantType = request.body.formData.get("grant_type");
    return (
      grantType === "authorization_code" && request.body.formData.has("code")
    );
  };

  onExchangeCompleted(exchange: Exchange) {
    const flow = this._activeFlow;

    if (exchange.id === flow?.redirectUriRequestId) {
      flow.observers.forEach((o) => console.log(o.getAssesment()));
    }
  }
}
