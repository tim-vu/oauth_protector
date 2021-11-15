import Exchange from "models/exchange";
import Request from "models/request";
import ThreatObserver, { ThreatStatus } from "oauth/threat_observer";

export class EavesDroppingAccessTokenLeakObserver extends ThreatObserver {
  constructor() {
    super("Threat: Eavesdropping Access Tokens");
    this._threat_status = ThreatStatus.PotentiallyProtected;
  }

  onTokenRequest(exchange: Exchange, request: Request) {
    const url = request.url;

    if (url.protocol === "https:") {
      this._threat_status = ThreatStatus.Protected;
      this._message = `The token endpoint ${url.href} is using https`;
      return;
    }

    this._threat_status = ThreatStatus.Vulnerable;
    this._message = `The token endpoint ${url.href} is not using https`;
  }
}
