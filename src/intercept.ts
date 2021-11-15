function hookXHRHttpRequest() {
  const XHR = XMLHttpRequest.prototype;

  const rawOpen = XHR.open;
  const rawSend = XHR.send;
  const rawSetRequestHeader = XHR.setRequestHeader;

  XHR.open = function (method, url) {
    this._request = {
      method: method,
      url: url,
      headers: {},
    };

    return rawOpen.apply(this, arguments);
  };

  XHR.setRequestHeader = function (header, value) {
    this._request.headers[header] = value;
    return rawSetRequestHeader.apply(this, arguments);
  };

  XHR.send = function (data) {
    this.addEventListener("load", function () {
      const responseHeaders = this.getAllResponseHeaders();

      const responseType = this.responseType;
      const includeResponseBody =
        responseType == "" || responseType == "text" || responseType == "json";

      let includeRequestBody =
        data instanceof String ||
        data instanceof URLSearchParams ||
        data instanceof FormData;

      window.postMessage("Request body type: " + typeof data);
      includeRequestBody = true;

      window.postMessage({
        type: "REQUEST_COMPLETED",
        request: {
          method: this._request.method,
          url: this._request.url,
          headers: this._request.headers,
          body: includeRequestBody ? data : undefined,
        },
        response: {
          statusCode: this.status,
          statusLine: this.statusText,
          headers: responseHeaders,
          body: includeResponseBody ? this.responseText : undefined,
        },
      });
    });

    return rawSend.apply(this, arguments);
  };
}

const run = () => {
  window.addEventListener(
    "message",
    (event) => {
      if (event.source != window) {
        return;
      }

      if (event.data.type && event.data.type == "REQUEST_COMPLETED") {
        console.log("Sending message");
        chrome.runtime.sendMessage(event.data);
      }
    },
    false
  );

  const injectedScript = hookXHRHttpRequest.toString();
  const element = document.createElement("script");
  element.text = `(${injectedScript})()`;
  element.onload = () => {
    (this as any).remove();
  };
  (document.head || document.documentElement).appendChild(element);
};

run();
