import Exchange from "models/exchange";
import Request from "models/request";
import Response from "models/response";
import ThreatObserver, { ThreatStatus } from "../../threat_observer";

export default class CodeHistoryLeakObserver extends ThreatObserver {
  constructor() {
    super('Leaking Authorization "codes" in the browser history');
  }

  onRedirectUriResponse(exchange: Exchange, response: Response) {
    if (this._threat_status != ThreatStatus.Unknown) return;

    if (Math.floor(response.statusCode / 100) != 3) {
      this._threat_status = ThreatStatus.Vulnerable;
      return;
    }

    this._threat_status = ThreatStatus.Protected;
  }
}
