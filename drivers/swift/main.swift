import Foundation

#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

#if canImport(Security)
import Security
#endif

import TrustedRouter

private enum DriverFailure: Error, CustomStringConvertible {
    case missingEnvironment(String)
    case invalidEnvironment(String)
    case forwarding(String)

    var description: String {
        switch self {
        case .missingEnvironment(let name):
            return "missing TR_CONFORMANCE_\(name)"
        case .invalidEnvironment(let message), .forwarding(let message):
            return message
        }
    }
}

private func environment(_ name: String) throws -> String {
    let key = "TR_CONFORMANCE_\(name)"
    guard let value = ProcessInfo.processInfo.environment[key] else {
        throw DriverFailure.missingEnvironment(name)
    }
    return value
}

#if canImport(Security)
/// Darwin URLSession does not honor the libcurl CA environment variables.
/// Anchor each physical forwarding session to the harness certificate and to
/// no system roots, preserving normal hostname verification for 127.0.0.1.
private final class TestCATrustDelegate: NSObject, URLSessionDelegate, @unchecked Sendable {
    private let certificate: SecCertificate

    init(certificatePath: String) throws {
        let pem = try String(contentsOfFile: certificatePath, encoding: .utf8)
        let base64 = pem
            .split(whereSeparator: \.isNewline)
            .filter { !$0.hasPrefix("-----") }
            .joined()
        guard let der = Data(base64Encoded: base64),
              let certificate = SecCertificateCreateWithData(nil, der as CFData)
        else {
            throw DriverFailure.invalidEnvironment("TR_CONFORMANCE_CA_CERT is not a PEM certificate")
        }
        self.certificate = certificate
        super.init()
    }

    func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let trust = challenge.protectionSpace.serverTrust
        else {
            completionHandler(.performDefaultHandling, nil)
            return
        }
        let anchors = [certificate] as CFArray
        guard SecTrustSetAnchorCertificates(trust, anchors) == errSecSuccess,
              SecTrustSetAnchorCertificatesOnly(trust, true) == errSecSuccess
        else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        var trustError: CFError?
        if SecTrustEvaluateWithError(trust, &trustError) {
            completionHandler(.useCredential, URLCredential(trust: trust))
        } else {
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }
}
#endif

/// Intercepts the SDK's logical TrustedRouter request and executes it against
/// the harness fault server. The SDK still sees an HTTPS
/// api.trustedrouter.com URL, so host-scoped behavior such as telemetry is
/// exercised by the real SDK request engine rather than reimplemented here.
private final class LogicalOriginProtocol: URLProtocol, @unchecked Sendable {
    private var task: URLSessionDataTask?
    private var forwardingSession: URLSession?

    override class func canInit(with request: URLRequest) -> Bool {
        request.url?.host?.lowercased() == "api.trustedrouter.com"
    }

    override class func canonicalRequest(for request: URLRequest) -> URLRequest {
        request
    }

    override func startLoading() {
        do {
            guard let logicalURL = request.url,
                  let logicalHost = logicalURL.host,
                  let physical = URLComponents(string: try environment("PHYSICAL_ORIGIN")),
                  let physicalScheme = physical.scheme,
                  let physicalHost = physical.host
            else {
                throw DriverFailure.forwarding("invalid logical URL or physical origin")
            }

            var destination = URLComponents(url: logicalURL, resolvingAgainstBaseURL: false)
            destination?.scheme = physicalScheme
            destination?.host = physicalHost
            destination?.port = physical.port
            guard let destinationURL = destination?.url else {
                throw DriverFailure.forwarding("could not construct forwarding URL")
            }

            var forwarded = request
            forwarded.url = destinationURL
            var logicalAuthority = logicalHost
            if let port = logicalURL.port {
                logicalAuthority += ":\(port)"
            }
            // Foundation may canonicalize restricted fields, but setting Host
            // here preserves the logical authority on implementations that
            // allow callers to provide it.
            forwarded.setValue(logicalAuthority, forHTTPHeaderField: "Host")

            let configuration = URLSessionConfiguration.ephemeral
            #if canImport(Security)
            let trustDelegate = try TestCATrustDelegate(certificatePath: environment("CA_CERT"))
            let session = URLSession(
                configuration: configuration,
                delegate: trustDelegate,
                delegateQueue: nil
            )
            #else
            // FoundationNetworking/libcurl consumes SSL_CERT_FILE and
            // CURL_CA_BUNDLE, set by run.py to TR_CONFORMANCE_CA_CERT.
            let session = URLSession(configuration: configuration)
            #endif
            forwardingSession = session
            task = session.dataTask(with: forwarded) { [weak self] data, response, error in
                guard let self else { return }
                if let error {
                    self.client?.urlProtocol(self, didFailWithError: error)
                    self.finishForwarding()
                    return
                }
                guard let response = response as? HTTPURLResponse else {
                    self.client?.urlProtocol(
                        self,
                        didFailWithError: DriverFailure.forwarding("physical origin returned a non-HTTP response")
                    )
                    self.finishForwarding()
                    return
                }

                var headers: [String: String] = [:]
                for (name, value) in response.allHeaderFields {
                    headers[String(describing: name)] = String(describing: value)
                }
                guard let logicalResponse = HTTPURLResponse(
                    url: logicalURL,
                    statusCode: response.statusCode,
                    httpVersion: "HTTP/1.1",
                    headerFields: headers
                ) else {
                    self.client?.urlProtocol(
                        self,
                        didFailWithError: DriverFailure.forwarding("could not construct logical HTTP response")
                    )
                    self.finishForwarding()
                    return
                }
                self.client?.urlProtocol(
                    self,
                    didReceive: logicalResponse,
                    cacheStoragePolicy: .notAllowed
                )
                if let data, !data.isEmpty {
                    self.client?.urlProtocol(self, didLoad: data)
                }
                self.client?.urlProtocolDidFinishLoading(self)
                self.finishForwarding()
            }
            task?.resume()
        } catch {
            client?.urlProtocol(self, didFailWithError: error)
            finishForwarding()
        }
    }

    override func stopLoading() {
        task?.cancel()
        forwardingSession?.invalidateAndCancel()
        task = nil
        forwardingSession = nil
    }

    private func finishForwarding() {
        task = nil
        forwardingSession?.finishTasksAndInvalidate()
        forwardingSession = nil
    }
}

private func logicalHTTPSBaseURL(_ rawValue: String) throws -> String {
    guard var components = URLComponents(string: rawValue),
          components.host?.lowercased() == "api.trustedrouter.com"
    else {
        throw DriverFailure.invalidEnvironment("invalid TR_CONFORMANCE_LOGICAL_BASE_URL")
    }
    components.scheme = "https"
    guard let value = components.url?.absoluteString else {
        throw DriverFailure.invalidEnvironment("could not construct logical HTTPS base URL")
    }
    return value
}

private func requestHeaders(_ rawValue: String) throws -> [String: String] {
    let data = Data(rawValue.utf8)
    guard let value = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
        throw DriverFailure.invalidEnvironment("TR_CONFORMANCE_HEADERS_JSON must be an object")
    }
    var result: [String: String] = [:]
    for (name, candidate) in value {
        guard let headerValue = candidate as? String else {
            throw DriverFailure.invalidEnvironment("request header values must be strings")
        }
        result[name] = headerValue
    }
    return result
}

private func normalizedValue(_ data: Data) -> Any {
    if data.isEmpty {
        return NSNull()
    }
    if let value = try? JSONSerialization.jsonObject(with: data, options: [.fragmentsAllowed]) {
        return value
    }
    if let value = String(data: data, encoding: .utf8) {
        return value
    }
    return ["body_base64": data.base64EncodedString()]
}

private func normalizedError(_ error: Error) -> [String: Any] {
    var value: [String: Any] = [
        "type": String(describing: type(of: error)),
        "message": String(describing: error),
    ]
    guard let routerError = error as? TrustedRouterError else {
        return value
    }

    let statusCode: Int
    let payload: [String: Any]?
    switch routerError {
    case .badRequest(let code, _, let body),
         .authentication(let code, _, let body),
         .permissionDenied(let code, _, let body),
         .notFound(let code, _, let body),
         .endpointNotSupported(let code, _, let body),
         .generic(let code, _, let body):
        statusCode = code
        payload = body
    case .rateLimit(let code, _, let body, _):
        statusCode = code
        payload = body
    case .internalError, .invalidResponse:
        return value
    }
    value["status_code"] = statusCode
    if let payload {
        value["body"] = payload
    }
    return value
}

private func emit(outcome: String, value: Any?, error: Error?) {
    let errorValue: Any
    if let error {
        errorValue = normalizedError(error)
    } else {
        errorValue = NSNull()
    }
    let result: [String: Any] = [
        "protocol_version": 1,
        "sdk": "swift",
        "scenario": ProcessInfo.processInfo.environment["TR_CONFORMANCE_SCENARIO"] ?? "unknown",
        "outcome": outcome,
        "value": value ?? NSNull(),
        "error": errorValue,
    ]
    if let data = try? JSONSerialization.data(
        withJSONObject: result,
        options: [.fragmentsAllowed, .sortedKeys]
    ), let line = String(data: data, encoding: .utf8) {
        print(line)
    } else {
        print("{\"protocol_version\":1,\"sdk\":\"swift\",\"scenario\":\"unknown\",\"outcome\":\"error\",\"value\":null,\"error\":{\"type\":\"SerializationError\",\"message\":\"could not serialize driver result\"}}")
    }
}

@main
private enum DriverMain {
    static func main() async {
        do {
            let configuration = URLSessionConfiguration.ephemeral
            configuration.protocolClasses = [LogicalOriginProtocol.self]
            let session = URLSession(configuration: configuration)

            let maxRetriesRaw = try environment("MAX_RETRIES")
            let timeoutRaw = try environment("TIMEOUT_MS")
            guard let maxRetries = Int(maxRetriesRaw), maxRetries >= 0 else {
                throw DriverFailure.invalidEnvironment("TR_CONFORMANCE_MAX_RETRIES must be non-negative")
            }
            guard let timeoutMilliseconds = Int(timeoutRaw), timeoutMilliseconds > 0 else {
                throw DriverFailure.invalidEnvironment("TR_CONFORMANCE_TIMEOUT_MS must be positive")
            }
            let telemetryRaw = try environment("TELEMETRY")
            guard telemetryRaw == "0" || telemetryRaw == "1" else {
                throw DriverFailure.invalidEnvironment("TR_CONFORMANCE_TELEMETRY must be 0 or 1")
            }

            let logicalBaseURL = try logicalHTTPSBaseURL(environment("LOGICAL_BASE_URL"))
            let client = try TrustedRouter(options: TrustedRouterOptions(
                apiKey: "tr-conformance-key",
                baseUrl: logicalBaseURL,
                controlBaseURL: logicalBaseURL,
                urlSession: session,
                maxRetries: maxRetries,
                regionalFailover: false,
                telemetry: telemetryRaw == "1",
                regionalAffinity: false
            ))

            let idempotencyKey = try environment("IDEMPOTENCY_KEY")
            let body = Data(try environment("BODY_JSON").utf8)
            let value: Data = try await client.request(
                method: environment("METHOD"),
                path: environment("PATH"),
                headers: requestHeaders(environment("HEADERS_JSON")),
                body: body,
                options: PerCallOptions(
                    idempotencyKey: idempotencyKey.isEmpty ? nil : idempotencyKey,
                    timeout: Double(timeoutMilliseconds) / 1_000.0
                ),
                plane: .inference
            )
            emit(outcome: "success", value: normalizedValue(value), error: nil)
            session.finishTasksAndInvalidate()
        } catch {
            emit(outcome: "error", value: nil, error: error)
        }
    }
}
