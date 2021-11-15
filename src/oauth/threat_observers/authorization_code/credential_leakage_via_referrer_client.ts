import Exchange from "models/exchange";
import Request from "models/request";
import Response from "models/response";
import ThreatObserver, { ThreatStatus } from "../../threat_observer";

export default class CredentialLeakageViaReferrerClient extends ThreatObserver {
  private static readonly ALLOWED_REFERRER_POLICIES: string[] = [
    "no-referrer",
    "origin",
    "origin-when-cross-origin",
    "same-origin",
    "strict-origin",
    "strict-origin-when-cross-origin",
  ];
  private _authorizationResponseId?: string;

  constructor() {
    super("Credential Leakage via Referrer Headers");
  }

  onAuthorizationRequest(exchange: Exchange, request: Request) {
    const query = request.url.query;

    if (!query.has("code_challenge")) return;

    this._threat_status = ThreatStatus.Protected;
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

    if (Math.floor(response.statusCode / 100) == 3) return;

    const referrerPolicy = response.headers.get("Referrer-Policy");

    if (
      CredentialLeakageViaReferrerClient.ALLOWED_REFERRER_POLICIES.includes(
        referrerPolicy
      )
    ) {
      this._threat_status = ThreatStatus.Protected;
      return;
    }

    this._threat_status = ThreatStatus.PotentiallyVulnerable;
  }
}
