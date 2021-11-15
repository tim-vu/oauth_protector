import Exchange from "models/exchange";
import Request from "models/request";
import Response from "models/response";
import { OAuthRequestType, OAuthResponseType } from "./oauth_message_type";

export enum ThreatStatus {
  Unknown,
  Protected,
  PotentiallyVulnerable,
  Vulnerable,
}

export default abstract class ThreatObserver {
  protected _threat_status: ThreatStatus = ThreatStatus.Unknown;
  protected _message: string;

  public get threatName() {
    return this._threatName;
  }

  private readonly _threatName: string;

  constructor(threatName: string) {
    this._threatName = threatName;
  }

  onRequest = (exchange: Exchange, request: Request) => {};

  onOAuthRequest(
    exchange: Exchange,
    request: Request,
    requestType: OAuthRequestType
  ) {}

  onOAuthResponse(
    exchange: Exchange,
    response: Response,
    responseType: OAuthResponseType
  ) {}

  onAuthorizationRequest(exchange: Exchange, request: Request) {}

  onResponse(exchange: Exchange, response: Response) {}

  public getAssesment() {
    const result: string[] = [];

    result.push(`Threat: ${this.threatName}`);
    result.push(`Status: ${ThreatStatus[this._threat_status]}`);

    if (this._message) result.push(this._message);

    return result.join("\r\n");
  }
}
