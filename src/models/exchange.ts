import Request from "./request";
import Response from "./response";

export default interface Exchange {
  id: string;
  type: string;
  tabId: number;
  initiator?: string;
  requests: Request[];
  responses: Response[];
}
