const run = () => {
  window.addEventListener(
    "message",
    (event) => {
      if (event.source != window) {
        return;
      }

      if (event.data.type) {
        chrome.runtime.sendMessage({
          type: event.data.type,
          ...event.data,
        });
      }
    },
    false
  );

  const element = document.createElement("script");
  element.src = chrome.extension.getURL("interceptor.js");
  element.onload = () => {
    element.remove();
  };

  (document.head || document.documentElement).appendChild(element);
};

//run();
