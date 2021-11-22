import Exchange from "models/exchange";
import Request from "models/request";
import Response from "models/response";
import ExchangeListener from "interfaces/exchange_listener";
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
import UserInformer from "interfaces/user_informer";
import ThreatObserver, { ThreatStatus } from "./threat_observer";

export class OAuthClientAssessor implements ExchangeListener {
  private _completedFlows: OAuthFlow[] = [];
  private _activeFlow?: OAuthFlow;

  constructor(private readonly userInformer: UserInformer) {}

  onRequest = (exchange: Exchange, request: Request) => {
    const requestInitiator = OAuthClientAssessor._getRequestInitiator(
      exchange,
      request
    );

    let sendRequest = true;

    if (exchange.type === "main_frame") {
      const isAuthRequest = OAuthClientAssessor._isAuthorizationRequest(
        requestInitiator,
        request
      );

      if (isAuthRequest[0]) {
        sendRequest = false;

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
      } else if (OAuthClientAssessor._isRedirectUriRequest(request)) {
        sendRequest = false;

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
      }
    }

    if (exchange.type === "xmlhttprequest") {
      if (OAuthClientAssessor._isAccessTokenRequest(request)) {
        sendRequest = false;

        const flow =
          this._activeFlow?.client ==
          OAuthClientAssessor._getRequestInitiator(exchange, request)
            ? this._activeFlow
            : undefined;

        if (!flow) {
          console.log("Access token request without active flow?");
          console.log("Initiator: " + request.url.origin);
          console.log(request);
        } else {
          flow.observers.forEach((o) => o.onTokenRequest(exchange, request));
        }
      }
    }

    if (sendRequest) {
      [
        ...this._completedFlows.flatMap((f) => f.observers),
        ...(this._activeFlow?.observers || []),
      ].forEach((o) => o.onRequest(exchange, request));
    }

    if (!this._activeFlow) return;

    this.updateObservers();
  };

  onResponse = (exchange: Exchange, response: Response) => {
    let sendResponse = true;

    if (exchange.type == "main_frame") {
      const flow = this._activeFlow;

      if (
        OAuthClientAssessor._isAuthorizationResponse(flow, exchange, response)
      ) {
        sendResponse = false;

        console.log(`Authorization response detected. Client: ${flow.client}`);
        console.log(response);

        flow.observers.forEach((o) =>
          o.onAuthorizationResponse(exchange, response)
        );
      } else if (exchange.id === flow?.redirectUriRequestId) {
        sendResponse = false;

        console.log(`Redirect-uri response detected. Client: ${flow.client}`);
        console.log(response);

        flow.observers.forEach((o) =>
          o.onRedirectUriResponse(exchange, response)
        );
      }
    }

    if (!this._activeFlow) return;

    if (sendResponse) {
      [
        ...this._completedFlows.flatMap((f) => f.observers),
        ...(this._activeFlow?.observers || []),
      ].forEach((o) => o.onResponse(exchange, response));
    }

    this.updateObservers();
  };

  private updateObservers() {
    const completedObservers = this._activeFlow.observers.filter(
      (o) => o.threatStatus != ThreatStatus.Unknown
    );

    if (completedObservers.length > 0) this.informUsers(completedObservers);

    this._activeFlow = {
      ...this._activeFlow,
      observers: this._activeFlow.observers.filter(
        (o) => o.threatStatus == ThreatStatus.Unknown
      ),
    };
  }

  private informUsers(completedObservers: ThreatObserver[]) {
    const toInform = completedObservers.filter(
      (o) =>
        o.threatStatus == ThreatStatus.Vulnerable ||
        o.threatStatus == ThreatStatus.PotentiallyVulnerable
    );

    if (toInform.length == 0) {
      return;
    }

    const message = toInform
      .map((o) => "Threat: " + o.threatName + "\n" + o.message)
      .join("\n");

    this.userInformer.sendMessage("OAuth vulnerability detected", message);
  }

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

  private static _isAuthorizationRequest = (
    initiator: string,
    request: Request
  ): [boolean, FlowType?] => {
    if (request.method !== "GET") return [false, undefined];

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

    const responseTypes =
      request.url.query.get("response_type")?.split(" ") || [];

    if (
      responseTypes.filter((r) => r in this.RESPONSE_TYPE_TO_FLOW_TYPE)
        .length == 0
    ) {
      console.log(
        `Unknown response_type ${responseTypes} encountered, ignoring request`
      );
      return [false, undefined];
    }

    return [
      true,
      OAuthClientAssessor.RESPONSE_TYPE_TO_FLOW_TYPE[
        responseTypes.find(
          (r) => r in OAuthClientAssessor.RESPONSE_TYPE_TO_FLOW_TYPE
        )
      ],
    ];
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
