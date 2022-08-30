import Exchange from "models/exchange";
import Request from "models/request";
import Response from "models/response";
import { createUrl } from "../../../../models/url";
import ThreatObserver, { ThreatStatus } from "../../threat_observer";

export default class TokenHistoryLeakObserver extends ThreatObserver {
  constructor() {
    super("Access Token Leak in Browser History");
  }

  onRedirectUriResponse(exchange: Exchange, response: Response) {
    if (this.threatStatus != ThreatStatus.Unknown) return;

    if (Math.floor(response.statusCode / 100) != 3) {
      this.threatStatus = ThreatStatus.Vulnerable;
      this.message = "The redirect-uri did not respond with a redirect";
      return;
    }

    const location = response.headers.get("location");

    const url = createUrl(location);

    if (!url.fragment) {
      this.threatStatus = ThreatStatus.Vulnerable;
      this.message = "The redirect uri did not override the fragment";
      return;
    }

    this.threatStatus = ThreatStatus.Protected;
  }
}
