import UserInformer from "interfaces/user_informer";

export default class NotificationInformer implements UserInformer {
  sendMessage(title: string, message: string): void {
    chrome.notifications.create(undefined, {
      title: title,
      message: message,
      type: "basic",
      iconUrl: "img/icon.png",
    });

    console.log("Sending notification");
  }
}
