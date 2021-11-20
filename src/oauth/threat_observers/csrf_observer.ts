import Exchange from "../../models/exchange";
import Request from "../../models/request";
import ThreatObserver, { ThreatStatus } from "../threat_observer";

export default class CsrfObserver extends ThreatObserver {
  private static readonly STATE_PARAMETER_MISSING_FROM_AUTHORIZATION_REQUESTmessage =
    "The authorization request does not contain the state paramester";
  private static readonly STATE_PARAMETER_MISSING_FROM_AUTHORIZATION_RESPONSEmessage =
    "The authorization response does not contain the state paramater";
  private static readonly STATE_PARAMTER_MISMATCHmessage =
    "This state parameter in the authorization response does not match the state parameter in the authorization request";

  static readonly STATE_QUERY_PARAMETER = "state";
  static readonly LOCATION_HEADER_NAME = "Location";

  private _state: string;

  constructor() {
    super("CSRF Attack against redirect-uri");
  }

  override onAuthorizationRequest(exchange: Exchange, request: Request) {
    const query = request.url.query;

    if (!query.has(CsrfObserver.STATE_QUERY_PARAMETER)) {
      this.threatStatus = ThreatStatus.PotentiallyVulnerable;
      this.message =
        CsrfObserver.STATE_PARAMETER_MISSING_FROM_AUTHORIZATION_REQUESTmessage;
      return;
    }

    this._state = query.get(CsrfObserver.STATE_QUERY_PARAMETER);
  }

  override onRedirectUriRequest(exchange: Exchange, request: Request) {
    if (this.threatStatus !== ThreatStatus.Unknown) {
      return;
    }

    const query = request.url.query;

    const state = query.get(CsrfObserver.STATE_QUERY_PARAMETER);

    if (!state) {
      this.threatStatus = ThreatStatus.Vulnerable;
      this.message =
        CsrfObserver.STATE_PARAMETER_MISSING_FROM_AUTHORIZATION_RESPONSEmessage;
      return;
    }

    if (this._state !== state) {
      this.threatStatus = ThreatStatus.Vulnerable;
      this.message = CsrfObserver.STATE_PARAMTER_MISMATCHmessage;
      return;
    }

    this.threatStatus = ThreatStatus.PotentiallyProtected;
    this.message = `State parameter ${state} present in authorization request and response`;
  }
}
