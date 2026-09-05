import Foundation
import UniformTypeIdentifiers
import WebKit

/// Serves the immutable React bundle from inside the signed application using a
/// private URL scheme. This gives JavaScript modules a consistent origin while
/// preventing the web view from reading arbitrary local files.
final class BundledWebSchemeHandler: NSObject, WKURLSchemeHandler {
    private let resourceRoot: URL

    init?(bundle: Bundle = .main) {
        guard let root = bundle.resourceURL?.appendingPathComponent("dist", isDirectory: true) else {
            return nil
        }
        self.resourceRoot = root.standardizedFileURL
    }

    func webView(_ webView: WKWebView, start urlSchemeTask: WKURLSchemeTask) {
        guard let requestURL = urlSchemeTask.request.url,
              requestURL.host == "app" else {
            fail(urlSchemeTask, code: 400)
            return
        }

        let requestedPath = requestURL.path == "/" ? "index.html" : String(requestURL.path.dropFirst())
        let fileURL = resourceRoot.appendingPathComponent(requestedPath).standardizedFileURL
        let rootPath = resourceRoot.path.hasSuffix("/") ? resourceRoot.path : resourceRoot.path + "/"
        guard fileURL.path.hasPrefix(rootPath),
              FileManager.default.fileExists(atPath: fileURL.path),
              let data = try? Data(contentsOf: fileURL) else {
            fail(urlSchemeTask, code: 404)
            return
        }

        let mimeType = UTType(filenameExtension: fileURL.pathExtension)?.preferredMIMEType
            ?? "application/octet-stream"
        let response = URLResponse(
            url: requestURL,
            mimeType: mimeType,
            expectedContentLength: data.count,
            textEncodingName: mimeType.hasPrefix("text/") || mimeType.contains("javascript") ? "utf-8" : nil
        )
        urlSchemeTask.didReceive(response)
        urlSchemeTask.didReceive(data)
        urlSchemeTask.didFinish()
    }

    func webView(_ webView: WKWebView, stop urlSchemeTask: WKURLSchemeTask) {}

    private func fail(_ task: WKURLSchemeTask, code: Int) {
        let response = HTTPURLResponse(
            url: task.request.url ?? URL(string: "velox://app/")!,
            statusCode: code,
            httpVersion: "HTTP/1.1",
            headerFields: ["Content-Type": "text/plain; charset=utf-8"]
        )!
        task.didReceive(response)
        task.didReceive(Data("Resource unavailable".utf8))
        task.didFinish()
    }
}
