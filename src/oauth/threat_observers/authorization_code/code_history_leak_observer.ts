import Exchange from "models/exchange";
import Request from "models/request";
import Response from "models/response";
import { createUrl } from "../../../models/url";
import ThreatObserver, { ThreatStatus } from "../../threat_observer";

export default class CodeHistoryLeakObserver extends ThreatObserver {
  constructor() {
    super('Leaking Authorization "codes" in the browser history');
  }

  onRedirectUriResponse(exchange: Exchange, response: Response) {
    if (this.threatStatus != ThreatStatus.Unknown) return;

    if (Math.floor(response.statusCode / 100) != 3) {
      this.threatStatus = ThreatStatus.Vulnerable;
      this.message = "The redirect-uri did not respond with a redirect";
      return;
    }

    const location = createUrl(response.headers.get("location"));

    if (!location.query.has("code")) {
      this.threatStatus = ThreatStatus.Protected;
      return;
    }
  }
}
