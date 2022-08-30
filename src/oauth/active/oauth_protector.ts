import ExchangeModifier, {
  Continue,
  isBlock,
  isContinue,
  MessageResult,
} from "interfaces/exchange_ modifier";
import Exchange from "models/exchange";
import OAuthFlowDetector, { OAuthMessage } from "oauth/oauth_flow_detector";
import Request from "models/request";
import Response from "models/response";
import OAuthFlow from "oauth/oauth_flow";
import ThreatPreventer from "./threat_preventer";

export default class OAuthProtector implements ExchangeModifier {
  private readonly _threatPreventers: Map<OAuthFlow, ThreatPreventer[]> =
    new Map();
  private readonly _flowDetector: OAuthFlowDetector;

  constructor() {
    this._flowDetector = new OAuthFlowDetector(this._onFlowCompleted);
  }

  private _getMessageResult(
    flow: OAuthFlow,
    invoker: (p: ThreatPreventer) => MessageResult
  ) {
    let result: MessageResult = {
      type: "continue",
    };
    let resultOwner: ThreatPreventer | null = null;

    for (const preventer of this._threatPreventers.get(flow)) {
      const r = invoker(preventer);

      if (isContinue(r)) continue;

      if (isContinue(result)) {
        result = r;
        resultOwner = preventer;
        continue;
      }

      if (isBlock(result) && isBlock(r)) continue;

      console.log(
        `Conflict detected. ThreatPreventer ${resultOwner} and ${preventer} do not agree on MessageResult`
      );
      break;
    }

    return result;
  }

  onRequest = (exchange: Exchange, request: Request) => {
    const result = this._flowDetector.onRequest(exchange, request);

    const cont: Continue = {
      type: "continue",
    };

    if (!result.type) return cont;

    if (result.type === OAuthMessage.AuthorizationRequest) {
      return this._getMessageResult(result.flow, (p) =>
        p.onAuthorizationRequest(exchange, request)
      );
    }

    if (result.type === OAuthMessage.RedirectUriRequest) {
      return this._getMessageResult(result.flow, (p) =>
        p.onRedirectUriRequest(exchange, request)
      );
    }

    if (result.type === OAuthMessage.TokenRequest) {
      return this._getMessageResult(result.flow, (p) =>
        p.onRedirectUriRequest(exchange, request)
      );
    }

    return cont;
  };

  onResponse = (exchange: Exchange, response: Response) => {
    const result = this._flowDetector.onResponse(exchange, response);

    const cont: MessageResult = {
      type: "continue",
    };

    if (!result.type) return cont;

    if (result.type === OAuthMessage.AuthorizationResponse) {
      return this._getMessageResult(result.flow, (p) =>
        p.onAuthorizationResponse(exchange, response)
      );
    }

    if (result.type === OAuthMessage.RedirectUriResponse) {
      return this._getMessageResult(result.flow, (p) =>
        p.onRedirectUriResponse(exchange, response)
      );
    }
  };

  private _onFlowCompleted = (flow: OAuthFlow) => {
    this._threatPreventers.delete(flow);
  };

  onExchangeCompleted: (exchange: Exchange) => void;
}
