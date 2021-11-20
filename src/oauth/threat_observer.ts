import Exchange from "models/exchange";
import Request from "models/request";
import Response from "models/response";

export enum ThreatStatus {
  Unknown,
  PotentiallyProtected,
  Protected,
  PotentiallyVulnerable,
  Vulnerable,
}

export default abstract class ThreatObserver {
  protected set threatStatus(threatStatus: ThreatStatus) {
    this._threatStatus = threatStatus;
  }

  private _threatStatus: ThreatStatus = ThreatStatus.Unknown;

  protected set message(message: string) {
    this._message = message;
  }

  private _message: string;

  public get threatName() {
    return this._threatName;
  }

  private readonly _threatName: string;

  constructor(threatName: string) {
    this._threatName = threatName;
  }

  onRequest(exchange: Exchange, request: Request) {}

  onAuthorizationRequest(exchange: Exchange, request: Request) {}

  onAuthorizationResponse(exchange: Exchange, response: Response) {}

  onRedirectUriRequest(exchange: Exchange, request: Request) {}

  onRedirectUriResponse(exchange: Exchange, response: Response) {}

  onTokenRequest(exchange: Exchange, request: Request) {}

  onResponse(exchange: Exchange, response: Response) {}

  public getAssesment() {
    const result: string[] = [];

    result.push(`Threat: ${this.threatName}`);
    result.push(`Status: ${ThreatStatus[this._threatStatus]}`);

    if (this.message) result.push(this.message);

    return result.join("\r\n");
  }
}
