import Exchange from "./exchange";
import Request from "./request";
import Response from "./response";

export default interface ExchangeListener {
  onRequest: (exchange: Exchange, request: Request) => void;
  onResponse: (exchange: Exchange, response: Response) => void;
  onExchangeCompleted: (exchange: Exchange) => void;
}
