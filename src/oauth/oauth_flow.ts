import ThreatObserver from "./threat_observer";

export enum FlowType {
  Implicit,
  AuthorizationCode,
}

export default interface OAuthFlow {
  client: string;
  authorizationServer: string;
  type: FlowType;
  observers: ThreatObserver[];
  redirectUriRequestId?: string;
}
