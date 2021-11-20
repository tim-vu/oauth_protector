import Exchange from "models/exchange";
import Request from "models/request";
import Response from "models/response";
import ThreatObserver, { ThreatStatus } from "../../threat_observer";

export default class CodeHistoryLeakObserver extends ThreatObserver {
  constructor() {
    super('Leaking Authorization "codes" in the browser history');
  }

  onRedirectUriResponse(exchange: Exchange, response: Response) {
    if (this.threatStatus != ThreatStatus.Unknown) return;

    if (Math.floor(response.statusCode / 100) != 3) {
      this.threatStatus = ThreatStatus.Vulnerable;
      return;
    }

    this.threatStatus = ThreatStatus.Protected;
  }
}
