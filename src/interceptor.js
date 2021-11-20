import { xhook } from "xhook";

xhook.before(function (request) {
  window.postMessage("REQUEST_COMPLETED", {
    method: request.method,
    url: request.url,
    headers: request.headers,
    body: request.body,
  });
});

xhook.after(function (request, response) {
  window.postMessage("RESPONSE_COMPLETED", {
    statusCode: response.status,
    status: response.statusText,
    headers: response.headers,
    body: response,
  });
});

console.log("Hooks enabled!");
