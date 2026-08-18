package com.trustedrouter.conformance;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.trustedrouter.CallOptions;
import com.trustedrouter.TrustedRouterClient;
import com.trustedrouter.TrustedRouterOptions;
import com.trustedrouter.errors.TrustedRouterException;
import com.trustedrouter.models.ChatCompletion;
import com.trustedrouter.models.ChatCompletionChunk;
import com.trustedrouter.models.ResponseObject;
import com.trustedrouter.oauth.OAuthToken;
import com.trustedrouter.requests.ChatRequest;
import com.trustedrouter.requests.ResponsesRequest;
import com.trustedrouter.streaming.EventStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ForkJoinPool;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import okhttp3.Dns;
import okhttp3.Interceptor;
import okhttp3.OkHttpClient;
import okhttp3.Response;

/** Protocol-v1 adapter that drives the checked-out SDK's generic inference request. */
public final class Driver {
    private static final Gson GSON = new GsonBuilder()
            .disableHtmlEscaping()
            .serializeNulls()
            .create();
    private static final String SDK = "java";

    private Driver() {}

    public static void main(String[] args) {
        JsonObject result;
        try {
            result = execute();
        } catch (Throwable error) {
            result = exceptionResult(error);
        }
        // The Python launcher filters Gradle lifecycle output and forwards only
        // this single protocol object.
        System.out.println(GSON.toJson(result));
    }

    private static JsonObject execute() throws Exception {
        final String logicalBaseUrl = required(
                "TR_CONFORMANCE_LOGICAL_BASE_URL", "LOGICAL_BASE_URL");
        final String physicalOrigin = required(
                "TR_CONFORMANCE_PHYSICAL_ORIGIN", "PHYSICAL_ORIGIN");
        final URI logical = new URI(logicalBaseUrl);
        final URI physical = new URI(physicalOrigin);
        if (logical.getHost() == null || physical.getHost() == null) {
            throw new IllegalArgumentException("logical and physical URLs must have hosts");
        }
        if (logical.getPort() != physical.getPort()) {
            throw new IllegalArgumentException(
                    "the DNS adapter requires logical and physical origins to use the same port");
        }
        if (!logical.getScheme().equalsIgnoreCase(physical.getScheme())) {
            throw new IllegalArgumentException(
                    "logical and physical origins must use the same scheme");
        }

        final String logicalHost = logical.getHost();
        final InetAddress physicalAddress = InetAddress.getByName(physical.getHost());
        Dns loopbackDns = new Dns() {
            @Override
            public List<InetAddress> lookup(String hostname) throws UnknownHostException {
                if (logicalHost.equalsIgnoreCase(hostname)) {
                    return Collections.singletonList(physicalAddress);
                }
                return Dns.SYSTEM.lookup(hostname);
            }
        };
        OkHttpClient.Builder httpClientBuilder = new OkHttpClient.Builder()
                .dns(loopbackDns)
                // Deliberately permissive. The SDK clone must disable hidden
                // recovery and redirects; doing it in the adapter would make
                // the isolation scenarios false positives.
                .retryOnConnectionFailure(true)
                .followRedirects(true)
                .followSslRedirects(true);
        final Map<String, String> defaultHeaders = headers(optional(
                "TR_CONFORMANCE_DEFAULT_HEADERS_JSON", "DEFAULT_HEADERS_JSON", "{}"));
        if (!defaultHeaders.isEmpty()) {
            httpClientBuilder.addInterceptor(new Interceptor() {
                @Override public Response intercept(Chain chain) throws IOException {
                    okhttp3.Request.Builder request = chain.request().newBuilder();
                    for (Map.Entry<String, String> header : defaultHeaders.entrySet()) {
                        request.header(header.getKey(), header.getValue());
                    }
                    return chain.proceed(request.build());
                }
            });
        }
        if ("https".equalsIgnoreCase(logical.getScheme())) {
            TlsConfig tls = tlsConfig(required("TR_CONFORMANCE_CA_CERT", "CA_CERT"));
            httpClientBuilder.sslSocketFactory(tls.context.getSocketFactory(), tls.trustManager);
        }
        OkHttpClient httpClient = httpClientBuilder.build();

        int maxRetries = nonNegativeInt(
                required("TR_CONFORMANCE_MAX_RETRIES", "MAX_RETRIES"), "MAX_RETRIES");
        long timeoutMillis = positiveLong(
                required("TR_CONFORMANCE_TIMEOUT_MS", "TIMEOUT_MS"), "TIMEOUT_MS");
        boolean telemetry = booleanValue(
                required("TR_CONFORMANCE_TELEMETRY", "TELEMETRY"), "TELEMETRY");

        TrustedRouterOptions clientOptions = TrustedRouterOptions.builder()
                .apiKey("tr-conformance-key")
                .baseUrl(logicalBaseUrl)
                .controlBaseUrl(logicalBaseUrl)
                .httpClient(httpClient)
                .timeoutMillis(timeoutMillis)
                .maxRetries(maxRetries)
                .regionalFailover(false)
                .telemetry(Boolean.valueOf(telemetry))
                .build();
        TrustedRouterClient client = new TrustedRouterClient(clientOptions);

        CallOptions.Builder call = CallOptions.builder()
                .headers(headers(required("TR_CONFORMANCE_HEADERS_JSON", "HEADERS_JSON")))
                .timeoutMillis(timeoutMillis);
        String idempotencyKey = optional(
                "TR_CONFORMANCE_IDEMPOTENCY_KEY", "IDEMPOTENCY_KEY", "");
        if (!idempotencyKey.isEmpty()) {
            call.idempotencyKey(idempotencyKey);
        }

        String method = required("TR_CONFORMANCE_METHOD", "METHOD");
        String path = required("TR_CONFORMANCE_PATH", "PATH");
        JsonElement parsedBody = JsonParser.parseString(
                required("TR_CONFORMANCE_BODY_JSON", "BODY_JSON"));
        JsonElement body = parsedBody.isJsonNull() ? null : parsedBody;

        String entrypoint = optional(
                "TR_CONFORMANCE_ENTRYPOINT", "ENTRYPOINT", "generic_json");
        JsonElement value;
        if ("generic_json".equals(entrypoint)) {
            value = generic(client, method, path, body, call.build());
        } else if ("chat_completions".equals(entrypoint)) {
            ChatCompletion completion = client.chatCompletions(
                    chatRequest(body, call.build()));
            value = completion.getRaw();
        } else if ("chat_stream_collect".equals(entrypoint)) {
            com.google.gson.JsonArray chunks = new com.google.gson.JsonArray();
            try (EventStream<ChatCompletionChunk> stream = client.chatCompletionsChunks(
                    chatRequest(body, call.build()))) {
                ChatCompletionChunk chunk;
                while ((chunk = stream.read()) != null) {
                    chunks.add(chunk.getRaw());
                }
            }
            value = chunks;
        } else if ("responses".equals(entrypoint)) {
            ResponseObject response = client.responses(responsesRequest(body, call.build()));
            value = response.getRaw();
        } else if ("oauth_exchange".equals(entrypoint)) {
            JsonObject object = body == null || !body.isJsonObject()
                    ? new JsonObject() : body.getAsJsonObject();
            OAuthToken token = client.exchangeOAuthKey(
                    stringValue(object, "code"),
                    nullableString(object, "code_verifier"),
                    nullableString(object, "code_challenge_method"));
            value = token.getRaw();
        } else {
            throw new IllegalArgumentException("unsupported ENTRYPOINT: " + entrypoint);
        }
        JsonObject result = envelope("success");
        result.add("value", value == null ? JsonNull.INSTANCE : value);
        result.add("error", JsonNull.INSTANCE);
        return result;
    }

    private static JsonElement generic(
            TrustedRouterClient client,
            String method,
            String path,
            JsonElement body,
            CallOptions options) throws Exception {
        String cancelRaw = optional(
                "TR_CONFORMANCE_CANCEL_AFTER_MS", "CANCEL_AFTER_MS", "");
        if (cancelRaw.isEmpty()) {
            return client.request(method, path, body, options);
        }
        final long cancelAfterMillis = positiveLong(cancelRaw, "CANCEL_AFTER_MS");
        // Exclude one-time worker creation from the cancellation interval. The
        // scenario is exercising cancellation of an in-flight body read, not
        // cancellation while the JVM is still starting its common pool.
        ForkJoinPool.commonPool().submit(() -> {}).join();
        final CompletableFuture<JsonElement> future = client.async().request(
                method, path, body, options);
        Thread canceller = new Thread(() -> {
            try {
                Thread.sleep(cancelAfterMillis);
                future.cancel(true);
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
            }
        }, "trusted-router-conformance-canceller");
        canceller.setDaemon(true);
        canceller.start();
        try {
            return future.get();
        } catch (ExecutionException wrapped) {
            Throwable cause = wrapped.getCause();
            if (cause instanceof Exception) {
                throw (Exception) cause;
            }
            throw wrapped;
        } catch (CancellationException cancelled) {
            throw cancelled;
        }
    }

    private static ChatRequest chatRequest(JsonElement body, CallOptions options) {
        ChatRequest.Builder request = ChatRequest.builder().callOptions(options);
        if (body != null && body.isJsonObject()) {
            for (Map.Entry<String, JsonElement> field : body.getAsJsonObject().entrySet()) {
                if (!"stream".equals(field.getKey())) {
                    request.parameter(field.getKey(), field.getValue());
                }
            }
        }
        return request.build();
    }

    private static ResponsesRequest responsesRequest(JsonElement body, CallOptions options) {
        ResponsesRequest.Builder request = ResponsesRequest.builder().callOptions(options);
        if (body != null && body.isJsonObject()) {
            for (Map.Entry<String, JsonElement> field : body.getAsJsonObject().entrySet()) {
                if (!"stream".equals(field.getKey())) {
                    request.parameter(field.getKey(), field.getValue());
                }
            }
        }
        return request.build();
    }

    private static String stringValue(JsonObject object, String name) {
        String value = nullableString(object, name);
        if (value == null || value.isEmpty()) {
            throw new IllegalArgumentException(name + " is required");
        }
        return value;
    }

    private static String nullableString(JsonObject object, String name) {
        JsonElement value = object.get(name);
        return value == null || value.isJsonNull() ? null : value.getAsString();
    }

    private static Map<String, String> headers(String json) {
        JsonElement parsed = JsonParser.parseString(json);
        if (!parsed.isJsonObject()) {
            throw new IllegalArgumentException("HEADERS_JSON must be a JSON object");
        }
        Map<String, String> values = new LinkedHashMap<String, String>();
        for (Map.Entry<String, JsonElement> entry : parsed.getAsJsonObject().entrySet()) {
            if (!entry.getValue().isJsonPrimitive()
                    || !entry.getValue().getAsJsonPrimitive().isString()) {
                throw new IllegalArgumentException("HEADERS_JSON values must be strings");
            }
            values.put(entry.getKey(), entry.getValue().getAsString());
        }
        return values;
    }

    private static JsonObject exceptionResult(Throwable error) {
        JsonObject detail = new JsonObject();
        String type = error.getClass().getSimpleName();
        detail.addProperty("type", type.isEmpty() ? error.getClass().getName() : type);
        detail.addProperty("message", error.getMessage() == null ? type : error.getMessage());
        if (error instanceof TrustedRouterException) {
            TrustedRouterException trustedRouter = (TrustedRouterException) error;
            detail.addProperty("status_code", trustedRouter.getStatusCode());
            JsonElement payload = trustedRouter.getPayload();
            if (payload != null) {
                detail.add("body", payload);
            }
        }
        JsonObject result = envelope("error");
        result.add("value", JsonNull.INSTANCE);
        result.add("error", detail);
        return result;
    }

    private static TlsConfig tlsConfig(String certificatePath) throws Exception {
        X509Certificate certificate;
        CertificateFactory certificates = CertificateFactory.getInstance("X.509");
        try (InputStream input = new FileInputStream(certificatePath)) {
            certificate = (X509Certificate) certificates.generateCertificate(input);
        }
        KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
        trustStore.load(null, null);
        trustStore.setCertificateEntry("trusted-router-conformance", certificate);

        TrustManagerFactory factory = TrustManagerFactory.getInstance(
                TrustManagerFactory.getDefaultAlgorithm());
        factory.init(trustStore);
        X509TrustManager trustManager = null;
        for (TrustManager candidate : factory.getTrustManagers()) {
            if (candidate instanceof X509TrustManager) {
                trustManager = (X509TrustManager) candidate;
                break;
            }
        }
        if (trustManager == null) {
            throw new IllegalStateException("no X509 trust manager for conformance CA");
        }
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(null, new TrustManager[] {trustManager}, new SecureRandom());
        return new TlsConfig(context, trustManager);
    }

    private static JsonObject envelope(String outcome) {
        JsonObject result = new JsonObject();
        result.addProperty("protocol_version", 1);
        result.addProperty("sdk", SDK);
        result.addProperty("scenario", optional(
                "TR_CONFORMANCE_SCENARIO", "SCENARIO", "unknown"));
        result.addProperty("outcome", outcome);
        return result;
    }

    private static String required(String preferred, String fallback) {
        String value = optional(preferred, fallback, null);
        if (value == null || value.isEmpty()) {
            throw new IllegalArgumentException(preferred + " is required");
        }
        return value;
    }

    private static String optional(String preferred, String fallback, String defaultValue) {
        String value = System.getenv(preferred);
        if (value == null) {
            value = System.getenv(fallback);
        }
        return value == null ? defaultValue : value;
    }

    private static int nonNegativeInt(String raw, String name) {
        int value = Integer.parseInt(raw);
        if (value < 0) {
            throw new IllegalArgumentException(name + " must be non-negative");
        }
        return value;
    }

    private static long positiveLong(String raw, String name) {
        long value = Long.parseLong(raw);
        if (value <= 0L) {
            throw new IllegalArgumentException(name + " must be positive");
        }
        return value;
    }

    private static boolean booleanValue(String raw, String name) {
        if ("1".equals(raw) || "true".equalsIgnoreCase(raw)) {
            return true;
        }
        if ("0".equals(raw) || "false".equalsIgnoreCase(raw)) {
            return false;
        }
        throw new IllegalArgumentException(name + " must be 0, 1, true, or false");
    }

    private static final class TlsConfig {
        private final SSLContext context;
        private final X509TrustManager trustManager;

        private TlsConfig(SSLContext context, X509TrustManager trustManager) {
            this.context = context;
            this.trustManager = trustManager;
        }
    }
}
