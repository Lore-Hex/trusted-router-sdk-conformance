package com.trustedrouter.conformance;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonPrimitive;
import com.trustedrouter.CallOptions;
import com.trustedrouter.TrustedRouterClient;
import com.trustedrouter.TrustedRouterOptions;
import com.trustedrouter.errors.TrustedRouterException;
import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import okhttp3.Dns;
import okhttp3.OkHttpClient;
import okhttp3.Response;
import okhttp3.ResponseBody;

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
                // A fault must surface to the SDK's retry engine rather than be
                // hidden by an OkHttp recovery inside one Call.
                .retryOnConnectionFailure(false)
                .followRedirects(false)
                .followSslRedirects(false);
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

        try (Response response = client.rawRequest(method, path, body, call.build())) {
            ResponseBody responseBody = response.body();
            String text = responseBody == null ? "" : responseBody.string();
            JsonElement value = decodedValue(text);
            if (response.isSuccessful()) {
                JsonObject result = envelope("success");
                result.add("value", value);
                result.add("error", JsonNull.INSTANCE);
                return result;
            }
            JsonObject error = new JsonObject();
            error.addProperty("type", "http_error");
            error.addProperty("message", "HTTP " + response.code());
            error.addProperty("status_code", response.code());
            error.add("body", value);
            JsonObject result = envelope("error");
            result.add("value", JsonNull.INSTANCE);
            result.add("error", error);
            return result;
        }
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

    private static JsonElement decodedValue(String text) {
        if (text == null || text.isEmpty()) {
            return JsonNull.INSTANCE;
        }
        try {
            return JsonParser.parseString(text);
        } catch (RuntimeException notJson) {
            return new JsonPrimitive(text);
        }
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
