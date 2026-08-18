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

private func optionalEnvironment(_ name: String, default defaultValue: String = "") -> String {
    ProcessInfo.processInfo.environment["TR_CONFORMANCE_\(name)"] ?? defaultValue
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
    private var forwardingTask: URLSessionDataTask?
    private var forwardingSession: URLSession?
    private var forwardingDelegate: PhysicalForwardingDelegate?

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
            let delegate: PhysicalForwardingDelegate
            #if canImport(Security)
            delegate = try PhysicalForwardingDelegate(
                owner: self,
                logicalURL: logicalURL,
                trustDelegate: TestCATrustDelegate(certificatePath: environment("CA_CERT"))
            )
            #else
            delegate = PhysicalForwardingDelegate(owner: self, logicalURL: logicalURL)
            #endif
            // The forwarding transport is incremental. The outer SDK task
            // therefore owns body deadlines and cancellation rather than
            // waiting behind a fully buffered adapter request.
            let session = URLSession(
                configuration: configuration,
                delegate: delegate,
                delegateQueue: nil
            )
            forwardingDelegate = delegate
            forwardingSession = session
            forwardingTask = session.dataTask(with: forwarded)
            forwardingTask?.resume()
        } catch {
            client?.urlProtocol(self, didFailWithError: error)
            finishForwarding()
        }
    }

    override func stopLoading() {
        forwardingTask?.cancel()
        forwardingSession?.invalidateAndCancel()
        forwardingTask = nil
        forwardingDelegate = nil
        forwardingSession = nil
    }

    private func finishForwarding() {
        forwardingTask = nil
        forwardingSession?.finishTasksAndInvalidate()
        forwardingSession = nil
        forwardingDelegate = nil
    }

    fileprivate func receive(_ response: HTTPURLResponse, logicalURL: URL) {
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
            fail(DriverFailure.forwarding("could not construct logical HTTP response"))
            return
        }
        client?.urlProtocol(self, didReceive: logicalResponse, cacheStoragePolicy: .notAllowed)
    }

    fileprivate func receive(_ data: Data) {
        if !data.isEmpty { client?.urlProtocol(self, didLoad: data) }
    }

    fileprivate func redirect(
        response: HTTPURLResponse,
        newRequest: URLRequest,
        logicalURL: URL
    ) {
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
            fail(DriverFailure.forwarding("could not construct logical redirect response"))
            return
        }
        // Feed the redirect into the OUTER URLSession. Its per-task SDK
        // delegate must reject it; the physical adapter merely preserves the
        // protocol event and never makes the policy decision itself.
        client?.urlProtocol(self, wasRedirectedTo: newRequest, redirectResponse: logicalResponse)
    }

    fileprivate func complete(_ error: Error?) {
        if let error {
            client?.urlProtocol(self, didFailWithError: error)
        } else {
            client?.urlProtocolDidFinishLoading(self)
        }
        finishForwarding()
    }

    private func fail(_ error: Error) {
        client?.urlProtocol(self, didFailWithError: error)
        finishForwarding()
    }
}

private final class PhysicalForwardingDelegate: NSObject, URLSessionDataDelegate, @unchecked Sendable {
    private weak var owner: LogicalOriginProtocol?
    private let logicalURL: URL
    private var redirected = false
    #if canImport(Security)
    private let trustDelegate: TestCATrustDelegate

    init(owner: LogicalOriginProtocol, logicalURL: URL, trustDelegate: TestCATrustDelegate) {
        self.owner = owner
        self.logicalURL = logicalURL
        self.trustDelegate = trustDelegate
    }
    #else
    init(owner: LogicalOriginProtocol, logicalURL: URL) {
        self.owner = owner
        self.logicalURL = logicalURL
    }
    #endif

    #if canImport(Security)
    func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        trustDelegate.urlSession(
            session, didReceive: challenge, completionHandler: completionHandler
        )
    }
    #endif

    func urlSession(
        _ session: URLSession,
        dataTask: URLSessionDataTask,
        didReceive response: URLResponse,
        completionHandler: @escaping (URLSession.ResponseDisposition) -> Void
    ) {
        guard let http = response as? HTTPURLResponse else {
            completionHandler(.cancel)
            owner?.complete(DriverFailure.forwarding("physical origin returned a non-HTTP response"))
            return
        }
        owner?.receive(http, logicalURL: logicalURL)
        completionHandler(.allow)
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
        owner?.receive(data)
    }

    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest,
        completionHandler: @escaping (URLRequest?) -> Void
    ) {
        redirected = true
        owner?.redirect(response: response, newRequest: request, logicalURL: logicalURL)
        // The outer logical task owns follow/reject policy.
        completionHandler(nil)
    }

    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        didCompleteWithError error: Error?
    ) {
        guard !redirected else { return }
        owner?.complete(error)
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

private func normalizedEncodable<T: Encodable>(_ value: T) throws -> Any {
    normalizedValue(try JSONEncoder().encode(value))
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
            configuration.httpAdditionalHeaders = try requestHeaders(
                optionalEnvironment("DEFAULT_HEADERS_JSON", default: "{}")
            )
            #if canImport(Security)
            let session = URLSession(
                configuration: configuration,
                delegate: try TestCATrustDelegate(certificatePath: environment("CA_CERT")),
                delegateQueue: nil
            )
            #else
            let session = URLSession(configuration: configuration)
            #endif

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
            let entrypoint = optionalEnvironment("ENTRYPOINT", default: "generic_json")
            let client: TrustedRouter?
            if entrypoint == "oauth_exchange" {
                // The public OAuth helper owns sanitizing the injected
                // session. Do not first construct an authenticated client,
                // which would reject a stale reserved session default before
                // that credential-free path gets a chance to remove it.
                client = nil
            } else {
                client = try TrustedRouter(options: TrustedRouterOptions(
                    apiKey: "tr-conformance-key",
                    baseUrl: logicalBaseURL,
                    controlBaseURL: logicalBaseURL,
                    urlSession: session,
                    maxRetries: maxRetries,
                    regionalFailover: false,
                    telemetry: telemetryRaw == "1",
                    regionalAffinity: false
                ))
            }

            let idempotencyKey = try environment("IDEMPOTENCY_KEY")
            let bodyData = Data(try environment("BODY_JSON").utf8)
            let bodyObject = try JSONSerialization.jsonObject(
                with: bodyData, options: [.fragmentsAllowed]
            )
            let callOptions = PerCallOptions(
                extraHeaders: try requestHeaders(environment("HEADERS_JSON")),
                idempotencyKey: idempotencyKey.isEmpty ? nil : idempotencyKey,
                timeout: Double(timeoutMilliseconds) / 1_000.0
            )
            let operation = Task<Any, Error> {
                switch entrypoint {
                case "generic_json":
                    guard let client else {
                        throw DriverFailure.invalidEnvironment("generic_json requires a client")
                    }
                    let value: Data = try await client.request(
                        method: try environment("METHOD"),
                        path: try environment("PATH"),
                        body: bodyData,
                        options: callOptions,
                        plane: .inference
                    )
                    return normalizedValue(value)
                case "chat_completions", "chat_stream_collect":
                    guard let client else {
                        throw DriverFailure.invalidEnvironment("chat entrypoint requires a client")
                    }
                    guard var body = bodyObject as? [String: Any],
                          let messages = body.removeValue(forKey: "messages")
                            as? [[String: Any]]
                    else {
                        throw DriverFailure.invalidEnvironment(
                            "chat entrypoint requires a messages array"
                        )
                    }
                    let model = (body.removeValue(forKey: "model") as? String)
                        ?? TrustedRouterConstants.autoModel
                    body.removeValue(forKey: "stream")
                    let completion = try await client.chatCompletions(
                        model: model,
                        messages: messages,
                        options: callOptions,
                        params: body
                    )
                    return try normalizedEncodable(completion)
                case "responses":
                    guard let client else {
                        throw DriverFailure.invalidEnvironment("responses entrypoint requires a client")
                    }
                    guard var body = bodyObject as? [String: Any],
                          let input = body.removeValue(forKey: "input")
                    else {
                        throw DriverFailure.invalidEnvironment(
                            "responses entrypoint requires input"
                        )
                    }
                    let model = (body.removeValue(forKey: "model") as? String)
                        ?? TrustedRouterConstants.autoModel
                    let instructions = body.removeValue(forKey: "instructions") as? String
                    body.removeValue(forKey: "stream")
                    let response = try await client.responses(
                        model: model,
                        input: input,
                        instructions: instructions,
                        options: callOptions,
                        params: body
                    )
                    return try normalizedEncodable(response)
                case "oauth_exchange":
                    guard let body = bodyObject as? [String: Any],
                          let code = body["code"] as? String
                    else {
                        throw DriverFailure.invalidEnvironment(
                            "oauth_exchange requires code"
                        )
                    }
                    let token = try await exchangeOAuthKey(
                        code: code,
                        codeVerifier: body["code_verifier"] as? String,
                        codeChallengeMethod: body["code_challenge_method"] as? String,
                        baseURL: logicalBaseURL,
                        urlSession: session
                    )
                    return try normalizedEncodable(token)
                default:
                    throw DriverFailure.invalidEnvironment(
                        "unsupported TR_CONFORMANCE_ENTRYPOINT: \(entrypoint)"
                    )
                }
            }
            let cancellation: Task<Void, Never>?
            if let cancelAfter = Int(optionalEnvironment("CANCEL_AFTER_MS")), cancelAfter > 0 {
                cancellation = Task {
                    try? await Task.sleep(nanoseconds: UInt64(cancelAfter) * 1_000_000)
                    operation.cancel()
                }
            } else {
                cancellation = nil
            }
            defer { cancellation?.cancel() }
            let value = try await operation.value
            emit(outcome: "success", value: value, error: nil)
            session.finishTasksAndInvalidate()
        } catch {
            emit(outcome: "error", value: nil, error: error)
        }
    }
}
