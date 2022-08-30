import Exchange from "models/exchange";
import Request from "models/request";
import Response from "models/response";

export function isContinue(messageResult: MessageResult) {
  return messageResult.type === "continue";
}

export interface Continue {
  readonly type: "continue";
}

export function isBlock(messageResult: MessageResult) {
  return messageResult.type === "block";
}

export interface Block {
  readonly type: "block";
}

export function isModify(messageResult: MessageResult) {
  return messageResult.type === "modify";
}

export interface Modify {
  readonly type: "modify";
  readonly url: string;
  readonly headers: ReadonlyMap<string, string>;
}

export type MessageResult = Continue | Block | Modify;

export default interface ExchangeModifier {
  onRequest: (exchange: Exchange, request: Request) => MessageResult;
  onResponse: (exchange: Exchange, response: Response) => MessageResult;
  onExchangeCompleted: (exchange: Exchange) => void;
}
