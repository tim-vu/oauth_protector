import Exchange from "models/exchange";
import ThreatObserver, { ThreatStatus } from "../../threat_observer";
import Request from "models/request";

export default class CodePhishingObserver extends ThreatObserver {
  constructor() {
    super('Authorization "code" Phishing');
  }

  onRedirectUriRequest(exchange: Exchange, request: Request) {
    const url = request.url;

    if (url.protocol === "https:") {
      this.threatStatus = ThreatStatus.Protected;
      this.message = `The redirect_uri ${url.href} is using https`;
      return;
    }

    this.threatStatus = ThreatStatus.Vulnerable;
    this.message = `The redirect_uri ${url.href} is not using https`;
  }
}
