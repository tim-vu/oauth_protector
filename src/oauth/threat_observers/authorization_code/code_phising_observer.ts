import Exchange from "models/exchange";
import ThreatObserver, { ThreatStatus } from "../../threat_observer";
import Request from "models/request";

export default class CodePhishingObserver extends ThreatObserver {
  constructor() {
    super('Authorization "code" Phishing');
  }

  onAuthorizationResponse(exchange: Exchange, request: Request) {
    const url = request.url;

    if (url.protocol === "https:") {
      this._threat_status = ThreatStatus.Protected;
      this._message = `The redirect_uri ${url.href} is using https`;
      return;
    }

    this._threat_status = ThreatStatus.Vulnerable;
    this._message = `The redirect_uri ${url.href} is not using https`;
  }
}
