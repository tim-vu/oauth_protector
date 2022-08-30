import Exchange from "../../../models/exchange";
import Request from "../../../models/request";
import ThreatObserver, { ThreatStatus } from "../threat_observer";
import { diceCoefficient } from "dice-coefficient";

export default class CsrfObserver extends ThreatObserver {
  private static readonly MAX_STATE_SIMILARITY: number = 0.95;

  private static readonly _clientToStateMap: Map<string, string[]> = new Map();

  private static readonly STATE_PARAMERTER_REUSE =
    "The state parameter is potentially being reused";

  private static readonly STATE_PARAMETER_MISSING_FROM_AUTHORIZATION_REQUEST =
    "The authorization request does not contain the state parameter";
  private static readonly STATE_PARAMETER_MISSING_FROM_AUTHORIZATION_RESPONSE =
    "The authorization response does not contain the state paramater";
  private static readonly STATE_PARAMTER_MISMATCH =
    "This state parameter in the authorization response does not match the state parameter in the authorization request";

  static readonly STATE_QUERY_PARAMETER = "state";
  static readonly LOCATION_HEADER_NAME = "Location";

  private _state: string;
  private readonly _client: string;

  constructor(client: string) {
    super("CSRF Attack against redirect-uri");
    this._client = client;
  }

  override onAuthorizationRequest(exchange: Exchange, request: Request) {
    const query = request.url.query;

    if (!query.has(CsrfObserver.STATE_QUERY_PARAMETER)) {
      this.threatStatus = ThreatStatus.PotentiallyVulnerable;
      this.message =
        CsrfObserver.STATE_PARAMETER_MISSING_FROM_AUTHORIZATION_REQUEST;
      return;
    }

    const state = query.get(CsrfObserver.STATE_QUERY_PARAMETER);

    const usedStates = CsrfObserver._clientToStateMap.get(this._client) || [];

    for (const usedState of usedStates) {
      const similarity = diceCoefficient(usedState, state);
      console.log("Similarity: " + similarity);
      if (similarity > CsrfObserver.MAX_STATE_SIMILARITY) {
        console.log("Used state: " + usedStates);
        this.threatStatus = ThreatStatus.Vulnerable;
        this.message = CsrfObserver.STATE_PARAMERTER_REUSE;
      }
    }

    CsrfObserver._clientToStateMap.set(this._client, [...usedStates, state]);
    this._state = state;
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
        CsrfObserver.STATE_PARAMETER_MISSING_FROM_AUTHORIZATION_RESPONSE;
      return;
    }

    if (this._state !== state) {
      this.threatStatus = ThreatStatus.Vulnerable;
      this.message = CsrfObserver.STATE_PARAMTER_MISMATCH;
      console.log("State parameter mismatch:");
      console.log(this._state);
      console.log(state);
      return;
    }

    console.log("State parameter: " + state);
    this.threatStatus = ThreatStatus.PotentiallyProtected;
  }
}
