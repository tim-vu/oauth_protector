import Exchange from "models/exchange";
import Request from "models/request";
import Response from "models/response";

export default interface ExchangeListener {
  onRequest: (exchange: Exchange, request: Request) => void;
  onResponse: (exchange: Exchange, response: Response) => void;
  onExchangeCompleted: (exchange: Exchange) => void;
}
