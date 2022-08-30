import Exchange from "models/exchange";
import Request from "models/request";
import Response from "models/response";
import ThreatObserver, { ThreatStatus } from "../threat_observer";

export class ClickJackingAttackObserver extends ThreatObserver {
  private static readonly X_FRAME_OPTIONS = "x-frame-options";
  private static readonly ALLOWED_DIRECTIVES = ["deny", "sameorigin"];

  private authorizationRequestId?: string;

  constructor() {
    super("Clickjacking Attack against Authorization");
  }

  override onAuthorizationRequest(exchange: Exchange, response: Request) {
    this.authorizationRequestId = exchange.id;
  }

  override onResponse(exchange: Exchange, response: Response) {
    if (
      this.threatStatus != ThreatStatus.Unknown ||
      exchange.id != this.authorizationRequestId ||
      Math.floor(response.statusCode / 100) == 3
    )
      return;

    const directive = response.headers.get(
      ClickJackingAttackObserver.X_FRAME_OPTIONS
    );

    if (
      !ClickJackingAttackObserver.ALLOWED_DIRECTIVES.includes(
        directive?.toLowerCase()
      )
    ) {
      this.threatStatus = ThreatStatus.Vulnerable;
      this.message =
        "The authorization page response does not correctly set the X-Frame-Options header";
      return;
    }

    this.threatStatus = ThreatStatus.Protected;
  }
}
