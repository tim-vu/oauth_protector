import Exchange from "../../models/exchange";
import Request from "../../models/request";
import ThreatObserver, { ThreatStatus } from "../threat_observer";

export default class CsrfObserver extends ThreatObserver {
  private static readonly STATE_PARAMETER_MISSING_FROM_AUTHORIZATION_REQUEST_MESSAGE =
    "The authorization request does not contain the state paramester";
  private static readonly STATE_PARAMETER_MISSING_FROM_AUTHORIZATION_RESPONSE_MESSAGE =
    "The authorization response does not contain the state paramater";
  private static readonly STATE_PARAMTER_MISMATCH_MESSAGE =
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
      this._threat_status = ThreatStatus.PotentiallyVulnerable;
      this._message =
        CsrfObserver.STATE_PARAMETER_MISSING_FROM_AUTHORIZATION_REQUEST_MESSAGE;
      return;
    }

    this._state = query.get(CsrfObserver.STATE_QUERY_PARAMETER);
  }

  override onAuthorizationResponse(exchange: Exchange, request: Request) {
    if (this._threat_status !== ThreatStatus.Unknown) {
      return;
    }

    const query = request.url.query;

    const state = query.get(CsrfObserver.STATE_QUERY_PARAMETER);

    if (!state) {
      this._threat_status = ThreatStatus.PotentiallyVulnerable;
      this._message =
        CsrfObserver.STATE_PARAMETER_MISSING_FROM_AUTHORIZATION_RESPONSE_MESSAGE;
      return;
    }

    if (this._state !== state) {
      this._threat_status = ThreatStatus.PotentiallyVulnerable;
      this._message = CsrfObserver.STATE_PARAMTER_MISMATCH_MESSAGE;
      return;
    }

    this._threat_status = ThreatStatus.Protected;
    this._message = `State parameter ${state} present in authorization request and response`;
  }
}
