import Exchange from "models/exchange";
import Response from "models/response";
import ThreatObserver, { ThreatStatus } from "../../threat_observer";

export class AccessTokenLeakInTransportObserver extends ThreatObserver {
  constructor() {
    super("Access Token Leak in Transport/Endpoints");
  }

  override onAuthorizationResponse(exchange: Exchange, response: Response) {
    const url = exchange.requests[exchange.requests.length - 1].url;

    if (url.protocol === "https:") {
      this.threatStatus = ThreatStatus.Protected;
      return;
    }

    this.threatStatus = ThreatStatus.Vulnerable;
    this.message = `The authorization response is not using https`;
  }
}
