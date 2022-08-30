import { MessageResult } from "interfaces/exchange_ modifier";
import Exchange from "models/exchange";
import Request from "models/request";
import Response from "models/response";

export default abstract class ThreatPreventer {
  onAuthorizationRequest(exchange: Exchange, request: Request): MessageResult {
    const result: MessageResult = {
      type: "continue",
    };

    return result;
  }

  onAuthorizationResponse(
    exchange: Exchange,
    response: Response
  ): MessageResult {
    const result: MessageResult = {
      type: "continue",
    };

    return result;
  }

  onRedirectUriRequest(exchange: Exchange, request: Request): MessageResult {
    const result: MessageResult = {
      type: "continue",
    };

    return result;
  }

  onRedirectUriResponse(exchange: Exchange, response: Response): MessageResult {
    const result: MessageResult = {
      type: "continue",
    };

    return result;
  }

  onTokenRequest(exchange: Exchange, request: Request): MessageResult {
    const result: MessageResult = {
      type: "continue",
    };

    return result;
  }
}
