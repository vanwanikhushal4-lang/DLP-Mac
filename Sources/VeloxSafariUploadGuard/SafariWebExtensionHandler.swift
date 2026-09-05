import Foundation
import SafariServices

final class SafariWebExtensionHandler: NSObject, NSExtensionRequestHandling {
    private let controlClient = SafariUploadGuardControlClient()

    func beginRequest(with context: NSExtensionContext) {
        let item = context.inputItems.first as? NSExtensionItem
        guard let message = item?.userInfo?[SFExtensionMessageKey] as? [String: Any],
              let action = message["action"] as? String else {
            complete(context, object: ["ok": false, "message": "Invalid extension request."])
            return
        }

        switch action {
        case "getWebUploadPolicy":
            controlClient.getSnapshot { [weak self] json in
                guard let self else { return }
                guard let object = self.jsonObject(json) else {
                    self.complete(context, object: ["ok": false, "message": "Invalid policy response."])
                    return
                }
                self.complete(context, object: [
                    "ok": object["ok"] as? Bool ?? false,
                    "mode": object["webUploadMode"] as? String ?? "enforce",
                    "protectedDirectoryNames": object["webUploadProtectedDirectories"] as? [String] ?? []
                ])
            }

        case "recordBrowserUploadAttempt":
            guard JSONSerialization.isValidJSONObject(message),
                  let data = try? JSONSerialization.data(withJSONObject: message),
                  let json = String(data: data, encoding: .utf8) else {
                complete(context, object: ["ok": false, "message": "Invalid upload event."])
                return
            }
            controlClient.recordUploadAttempt(json) { [weak self] response in
                guard let self else { return }
                self.complete(
                    context,
                    object: self.jsonObject(response) ?? ["ok": false, "message": "Invalid event response."]
                )
            }

        default:
            complete(context, object: ["ok": false, "message": "Unsupported extension action."])
        }
    }

    private func jsonObject(_ json: String) -> [String: Any]? {
        guard let data = json.data(using: .utf8) else { return nil }
        return try? JSONSerialization.jsonObject(with: data) as? [String: Any]
    }

    private func complete(_ context: NSExtensionContext, object: [String: Any]) {
        let response = NSExtensionItem()
        response.userInfo = [SFExtensionMessageKey: object]
        context.completeRequest(returningItems: [response])
    }
}
