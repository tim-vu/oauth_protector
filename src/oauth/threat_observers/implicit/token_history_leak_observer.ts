import Exchange from "models/exchange";
import Request from "models/request";
import Response from "models/response";
import { createUrl } from "../../../models/url";
import ThreatObserver, { ThreatStatus } from "../../threat_observer";

export default class TokenHistoryLeakObserver extends ThreatObserver {
  private _authorizationResponseId?: string;

  constructor() {
    super("Access Token Leak in Browser History");
  }

  onAuthorizationResponse(exchange: Exchange, request: Request) {
    this._authorizationResponseId = exchange.id;
  }

  onResponse(exchange: Exchange, response: Response) {
    if (
      this._threat_status != ThreatStatus.Unknown ||
      exchange.id !== this._authorizationResponseId
    )
      return;

    if (Math.floor(response.statusCode / 100) != 3) {
      this._threat_status = ThreatStatus.PotentiallyVulnerable;
      return;
    }

    const location =
      response.headers.get("Location") || response.headers.get("location");

    const url = createUrl(location);

    if (!url.fragment) {
      this._threat_status = ThreatStatus.PotentiallyVulnerable;
      return;
    }

    this._threat_status = ThreatStatus.Protected;
  }
}
