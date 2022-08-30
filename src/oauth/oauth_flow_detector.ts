import Exchange from "models/exchange";
import Request from "models/request";
import Response from "models/response";
import { createUrl } from "../models/url";
import OAuthFlow, { FlowType } from "./oauth_flow";
import { OAuthClientAssessor } from "./passive/oauth_client_assessor";

export enum OAuthMessage {
  AuthorizationRequest = 1,
  AuthorizationResponse = 2,
  RedirectUriRequest = 3,
  RedirectUriResponse = 4,
  TokenRequest = 5,
}

export default class OAuthFlowDetector {
  private static readonly AUTHORIZATION_REQUEST_KEEP_ALIVE = 3 * 60 * 1000;
  private static readonly REDIRECT_URI_REQUEST_KEE_ALIVE: number = 3000;

  private readonly _flows: Set<OAuthFlow> = new Set();

  constructor(flowCompletedCallback: (flow: OAuthFlow) => void) {
    this.onFlowCompletedCallback = flowCompletedCallback;
  }

  private readonly onFlowCompletedCallback: (flow: OAuthFlow) => void;

  private _getSimilarFlow(flow: OAuthFlow): OAuthFlow | undefined {
    return Array.from(this._flows.values()).find(
      (f) =>
        f.clientId === flow.clientId &&
        f.state === flow.state &&
        f.nonce === flow.nonce
    );
  }

  onRequest(
    exchange: Exchange,
    request: Request
  ): { type?: OAuthMessage; flow?: OAuthFlow } {
    const requestInitiator = OAuthFlowDetector._getRequestInitiator(
      exchange,
      request
    );

    if (exchange.type === "main_frame") {
      const result = OAuthFlowDetector._isAuthorizationRequest(
        requestInitiator,
        request
      );

      if (result.isAuthRequest) {
        const flow: OAuthFlow = {
          client: requestInitiator,
          clientId: request.url.query.get("client_id"),
          state: request.url.query.get("state"),
          nonce: request.url.query.get("nonce"),
          redirectUri: request.url.query.get("redirect_uri"),
          authorizationServer: new Set([request.url.origin]),
          type: result.flowType,
        };

        console.log(`Authorization request detected. Client: ${flow.client}`);
        console.log(request);

        const existingFlow = this._getSimilarFlow(flow);

        if (existingFlow) {
          console.log(
            `Detected a similar flow. Client: ${existingFlow.client}`
          );
          existingFlow.authorizationServer.add(request.url.origin);
          return {};
        }

        this._flows.add(flow);

        setTimeout(
          () => this._flowCompleted(flow),
          OAuthFlowDetector.AUTHORIZATION_REQUEST_KEEP_ALIVE
        );

        return {
          type: OAuthMessage.AuthorizationRequest,
          flow: flow,
        };
      }

      if (OAuthFlowDetector._isRedirectUriRequest(request)) {
        const flow = Array.from(this._flows.values()).find(
          (f) =>
            request.url.origin === f.client ||
            request.url.href.includes(f.redirectUri)
        );

        if (!flow) {
          console.log("CSRF Attack detected?");
          console.log("Initiator: " + request.url.origin);
          console.log(request);
          return {};
        }

        console.log(`Redirect uri request detected. Client: ${flow.client}`);
        console.log(request);

        flow.redirectUriRequestId = exchange.id;

        return {
          type: OAuthMessage.RedirectUriRequest,
          flow: flow,
        };
      }
    }

    if (exchange.type === "xmlhttprequest") {
      if (OAuthFlowDetector._isAccessTokenRequest(request)) {
        const flow = Array.from(this._flows.values()).find(
          (f) => requestInitiator === f.client
        );

        if (!flow) {
          console.log("Access token request without active flow?");
          console.log("Initiator: " + request.url.origin);
          console.log(request);

          return {};
        }

        console.log("Access token request detected");
        console.log(request);

        return {
          type: OAuthMessage.TokenRequest,
          flow: flow,
        };
      }
    }

    return {};
  }

  onResponse(
    exchange: Exchange,
    response: Response
  ): { type?: OAuthMessage; flow?: OAuthFlow } {
    if (exchange.type == "main_frame") {
      const [isAuthResponse, flow] = this.isAuthorizationResponse(
        exchange,
        response
      );

      if (isAuthResponse) {
        console.log(`Authorization response detected. Client: ${flow.client}`);
        console.log(response);

        return {
          type: OAuthMessage.AuthorizationResponse,
          flow: flow,
        };
      }

      const redirectFlow = Array.from(this._flows.values()).find(
        (f) => f.redirectUriRequestId === exchange.id
      );

      if (redirectFlow) {
        console.log(
          `Redirect-uri response detected. Client: ${redirectFlow.client}`
        );

        setTimeout(
          () => this._flowCompleted(redirectFlow),
          OAuthFlowDetector.REDIRECT_URI_REQUEST_KEE_ALIVE
        );

        return {
          type: OAuthMessage.RedirectUriResponse,
          flow: redirectFlow,
        };
      }

      return {};
    }

    return {};
  }

  private _flowCompleted(flow: OAuthFlow): void {
    if (!this._flows.has(flow)) return;

    console.log("Flow completed");
    console.log(flow);

    this._flows.delete(flow);
    this.onFlowCompletedCallback(flow);
  }

  private static _getRequestInitiator(exchange: Exchange, request: Request) {
    if (exchange.requests.length === 1) return exchange.initiator;

    //Multiple requests in this exchange, there must be a redirect
    //The hostname which served this redirect might be different from the exchange's initiator

    return exchange.requests[exchange.requests.length - 2].url.origin;
  }

  private static readonly RESPONSE_TYPE_TO_FLOW_TYPE: Record<string, FlowType> =
    {
      code: FlowType.AuthorizationCode,
      token: FlowType.Implicit,
    };
  private static _isAuthorizationRequest = (
    initiator: string,
    request: Request
  ): { isAuthRequest: boolean; flowType?: FlowType } => {
    if (request.method !== "GET") return { isAuthRequest: false };

    const hasParameters =
      request.url.query.has("client_id") &&
      request.url.query.has("response_type");

    if (!hasParameters) return { isAuthRequest: false };

    const responseTypes =
      request.url.query.get("response_type")?.split(" ") || [];

    if (
      responseTypes.filter((r) => r in this.RESPONSE_TYPE_TO_FLOW_TYPE)
        .length == 0
    ) {
      console.log(
        `Unknown response_type ${responseTypes} encountered, ignoring request`
      );
      return { isAuthRequest: false };
    }

    return {
      isAuthRequest: true,
      flowType:
        OAuthFlowDetector.RESPONSE_TYPE_TO_FLOW_TYPE[
          responseTypes.find(
            (r) => r in OAuthFlowDetector.RESPONSE_TYPE_TO_FLOW_TYPE
          )
        ],
    };
  };

  private isAuthorizationResponse = (
    exchange: Exchange,
    response: Response
  ): [boolean, OAuthFlow | null] => {
    //The spec shows a redirect with status code 302

    const isRedirect = Math.floor(response.statusCode / 100) == 3;

    if (!isRedirect) return [false, null];

    const initiator =
      exchange.requests[exchange.requests.length - 1].url.origin;

    const flow = Array.from(this._flows.values()).find((f) =>
      f.authorizationServer.has(initiator)
    );

    if (!flow) return [false, null];

    const location = createUrl(response.headers.get("location"), initiator);

    const query = location.query;

    if (query.has("code")) {
      if (response.statusCode != 302) {
        console.log(
          "Authorization response detected with statuscode different from 302"
        );
        console.log(response);
      }

      return [true, flow];
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

      return [true, flow];
    }

    return [false, null];
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
}
