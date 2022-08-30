import ThreatObserver from "./passive/threat_observer";

export enum FlowType {
  Implicit,
  AuthorizationCode,
}

export default interface OAuthFlow {
  client: string;
  clientId: string;
  state?: string;
  nonce?: string;
  redirectUri: string;
  authorizationServer: Set<string>;
  type: FlowType;
  observers?: ThreatObserver[];
  redirectUriRequestId?: string;
}
