import Exchange from "./models/exchange";
import Request from "./models/request";
import Response from "./models/response";
import { OAuthClientAssessor } from "./oauth/oauth_client_assessor";
import { createUrl } from "./models/url";

const ALL_REQUESTS_FILTER: chrome.webRequest.RequestFilter = {
  urls: ["<all_urls>"],
};

const partialExchanges = new Map<string, Exchange>();
const exchangeListener = new OAuthClientAssessor();

chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    const body = details.requestBody
      ? {
          error: details.requestBody?.error,
          formData: details.requestBody?.formData
            ? new Map(
                Object.keys(details.requestBody?.formData!).map((key) => [
                  key,
                  details.requestBody?.formData![key][0],
                ])
              )
            : undefined,
          raw: details.requestBody?.raw
            ? details.requestBody?.raw.map((u) => ({
                bytes: u.bytes,
                file: u.file,
              }))
            : undefined,
        }
      : undefined;

    const request: Request = {
      method: details.method,
      headers: new Map(),
      url: createUrl(details.url),
      body,
    };

    const exchange = partialExchanges.get(details.requestId);

    if (!exchange) {
      partialExchanges.set(details.requestId, {
        id: details.requestId,
        tabId: details.tabId,
        initiator: details.initiator,
        type: details.type,
        requests: [request],
        responses: [],
      });
      return;
    }

    partialExchanges.set(details.requestId, {
      ...exchange,
      requests: [...exchange.requests, request],
    });
  },
  ALL_REQUESTS_FILTER,
  ["extraHeaders", "requestBody"]
);

chrome.webRequest.onBeforeSendHeaders.addListener(
  (details) => {
    const exchange = partialExchanges.get(details.requestId);

    if (!exchange) {
      return;
    }

    const headers = new Map<string, string>(
      details.requestHeaders
        .filter((h) => h.value)
        .map((h) => [h.name, h.value])
    );

    const partialRequest = exchange.requests[exchange.requests.length - 1];

    const fullRequest = {
      ...partialRequest,
      headers,
    };

    const newExchange = {
      ...exchange,
      requests: [...exchange.requests.slice(0, -1), fullRequest],
    };

    partialExchanges.set(details.requestId, newExchange);

    exchangeListener.onRequest(newExchange, fullRequest);
  },
  ALL_REQUESTS_FILTER,
  ["requestHeaders", "extraHeaders"]
);

const processResponse = (
  details: chrome.webRequest.WebResponseHeadersDetails
) => {
  const exchange = partialExchanges.get(details.requestId);

  if (!exchange) return;

  const headers = details.responseHeaders
    ? new Map(
        details.responseHeaders
          .filter((h) => h.value)
          .map((h) => [h.name, h.value])
      )
    : new Map();

  const response: Response = {
    statusCode: details.statusCode,
    statusLine: details.statusLine,
    headers,
  };

  const newExchange = {
    ...exchange,
    responses: [...exchange.responses, response],
  };

  partialExchanges.set(details.requestId, newExchange);

  exchangeListener.onResponse(newExchange, response);
};

chrome.webRequest.onBeforeRedirect.addListener(
  processResponse,
  ALL_REQUESTS_FILTER,
  ["responseHeaders"]
);
chrome.webRequest.onResponseStarted.addListener(
  processResponse,
  ALL_REQUESTS_FILTER,
  ["responseHeaders"]
);

chrome.webRequest.onCompleted.addListener((details) => {
  const exchange = partialExchanges.get(details.requestId);

  if (
    !exchange ||
    (exchange.type !== "main_frame" && exchange.type !== "xmlhttprequest")
  )
    return;

  exchangeListener.onExchangeCompleted(exchange);
  partialExchanges.delete(exchange.id);
}, ALL_REQUESTS_FILTER);

chrome.runtime.onMessage.addListener(function (request, sender) {
  console.log(request);
});
