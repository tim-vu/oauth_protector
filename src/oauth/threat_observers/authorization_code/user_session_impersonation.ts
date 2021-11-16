import Exchange from "models/exchange";
import Request from "models/request";
import ThreatObserver, { ThreatStatus } from "../../threat_observer";

export class UserSessionImpersonationObserver extends ThreatObserver {
  constructor() {
    super("User Session Impersonation");
  }

  override onRedirectUriRequest(exchange: Exchange, request: Request) {
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