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

  constructor() {
    super("Credential Leakage via Referrer Headers");
  }

  onAuthorizationRequest(exchange: Exchange, request: Request) {
    const query = request.url.query;

    if (!query.has("code_challenge")) return;

    this.threatStatus = ThreatStatus.Protected;
  }

  onRedirectUriResponse(exchange: Exchange, response: Response) {
    if (this.threatStatus != ThreatStatus.Unknown) return;

    if (Math.floor(response.statusCode / 100) == 3) {
      //TODO: handle the case where the redirect includes the code/state parameter
      this.threatStatus = ThreatStatus.Protected;
      return;
    }

    const referrerPolicy = response.headers.get("Referrer-Policy");

    if (
      CredentialLeakageViaReferrerClient.ALLOWED_REFERRER_POLICIES.includes(
        referrerPolicy
      )
    ) {
      this.threatStatus = ThreatStatus.Protected;
      return;
    }

    this.threatStatus = ThreatStatus.PotentiallyVulnerable;
    this.message =
      "The redirect-uri does not properly set the Referrer-Policy header";
  }
}
