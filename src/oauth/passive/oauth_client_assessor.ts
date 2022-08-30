import Exchange from "models/exchange";
import Request from "models/request";
import Response from "models/response";
import ExchangeListener from "interfaces/exchange_listener";
import OAuthFlow, { FlowType } from "../oauth_flow";
import CsrfObserver from "./threat_observers/csrf_observer";
import CodePhishingObserver from "./threat_observers/authorization_code/code_phising_observer";
import CodeHistoryLeakObserver from "./threat_observers/authorization_code/code_history_leak_observer";
import TokenHistoryLeakObserver from "./threat_observers/implicit/token_leak_in_history";
import CredentialLeakageViaReferrerClientObserver from "./threat_observers/authorization_code/credential_leakage_via_referrer_client";
import { UserSessionImpersonationObserver } from "./threat_observers/authorization_code/user_session_impersonation";
import { EavesDroppingAccessTokenLeakObserver } from "./threat_observers/authorization_code/eavesdropping_access_token";
import { AccessTokenLeakInTransportObserver } from "./threat_observers/implicit/token_leak_in_transport";
import { ClickJackingAttackObserver } from "./threat_observers/clickjacking_attack_observer";
import UserInformer from "interfaces/user_informer";
import ThreatObserver, { ThreatStatus } from "./threat_observer";
import OAuthFlowDetector, { OAuthMessage } from "../oauth_flow_detector";

export class OAuthClientAssessor implements ExchangeListener {
  private readonly _threatObservers: Map<OAuthFlow, ThreatObserver[]> =
    new Map();
  private readonly _flowDetector: OAuthFlowDetector;

  constructor(private readonly userInformer: UserInformer) {
    this._flowDetector = new OAuthFlowDetector(this._onFlowCompleted);
  }

  onRequest = (exchange: Exchange, request: Request) => {
    const result = this._flowDetector.onRequest(exchange, request);

    if (!result.type) {
      return;
    }

    if (result.type === OAuthMessage.AuthorizationRequest) {
      const observers = OAuthClientAssessor._createObservers(
        result.flow.type,
        result.flow
      );

      this._threatObservers.set(result.flow, observers);

      observers.forEach((o) => o.onAuthorizationRequest(exchange, request));
    }

    if (result.type === OAuthMessage.RedirectUriRequest) {
      const observers = this._threatObservers.get(result.flow);

      observers.forEach((o) => o.onRedirectUriRequest(exchange, request));
    }

    if (result.type === OAuthMessage.TokenRequest) {
      const observers = this._threatObservers.get(result.flow);

      observers.forEach((o) => o.onTokenRequest(exchange, request));
    }

    if (!result.flow) return;

    this.updateObservers(result.flow);
  };

  onResponse = (exchange: Exchange, response: Response) => {
    const result = this._flowDetector.onResponse(exchange, response);

    const targetOrigin =
      exchange.requests[exchange.requests.length - 1].url.origin;

    if (!result.type) {
      Array.from(this._threatObservers.entries())
        .filter(([flow, obs]) => flow.authorizationServer.has(targetOrigin))
        .flatMap(([flow, obs]) => obs)
        .forEach((obs) => obs.onResponse(exchange, response));
    }

    if (result.type === OAuthMessage.AuthorizationResponse) {
      const observers = this._threatObservers.get(result.flow);

      observers.forEach((o) => o.onAuthorizationResponse(exchange, response));
    }

    if (result.type === OAuthMessage.RedirectUriResponse) {
      const observers = this._threatObservers.get(result.flow);

      observers.forEach((o) => o.onRedirectUriResponse(exchange, response));
    }

    if (!result.flow) return;

    this.updateObservers(result.flow);
  };

  private _onFlowCompleted = (flow: OAuthFlow) => {
    this._threatObservers.delete(flow);
  };

  private updateObservers(flow: OAuthFlow) {
    const observers = this._threatObservers.get(flow);

    const completedObservers = observers.filter(
      (o) => o.threatStatus != ThreatStatus.Unknown
    );

    if (completedObservers.length > 0) this.informUsers(completedObservers);

    this._threatObservers.set(
      flow,
      observers.filter((o) => o.threatStatus == ThreatStatus.Unknown)
    );
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

  private static _createObservers(flowType: FlowType, flow: OAuthFlow) {
    if (flowType == FlowType.AuthorizationCode) {
      return [
        new CsrfObserver(flow.client),
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
        new CsrfObserver(flow.client),
        new ClickJackingAttackObserver(),
        new TokenHistoryLeakObserver(),
        new AccessTokenLeakInTransportObserver(),
      ];
    }
  }

  onExchangeCompleted(exchange: Exchange) {}
}
