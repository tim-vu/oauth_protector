import Exchange from "models/exchange";
import Request from "models/request";
import ThreatObserver, { ThreatStatus } from "../../threat_observer";

export class EavesDroppingAccessTokenLeakObserver extends ThreatObserver {
  constructor() {
    super("Eavesdropping Access Tokens");
  }

  onTokenRequest(exchange: Exchange, request: Request) {
    const url = request.url;

    if (url.protocol === "https:") {
      this.threatStatus = ThreatStatus.Protected;
      this.message = `The token endpoint ${url.href} is using https`;
      return;
    }

    this.threatStatus = ThreatStatus.Vulnerable;
    this.message = `The token endpoint ${url.href} is not using https`;
  }
}
