package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	trustedrouter "github.com/Lore-Hex/trusted-router-go"
)

type normalizedError struct {
	Type       string `json:"type"`
	Message    string `json:"message"`
	StatusCode *int   `json:"status_code,omitempty"`
}

type result struct {
	ProtocolVersion int              `json:"protocol_version"`
	SDK             string           `json:"sdk"`
	Scenario        string           `json:"scenario"`
	Outcome         string           `json:"outcome"`
	Value           any              `json:"value"`
	Error           *normalizedError `json:"error"`
}

func environment(name string) (string, error) {
	key := "TR_CONFORMANCE_" + name
	value, present := os.LookupEnv(key)
	if !present {
		return "", fmt.Errorf("missing %s", key)
	}
	return value, nil
}

func emit(outcome string, value any, err error) {
	output := result{
		ProtocolVersion: 1,
		SDK:             "go",
		Scenario:        os.Getenv("TR_CONFORMANCE_SCENARIO"),
		Outcome:         outcome,
		Value:           value,
	}
	if output.Scenario == "" {
		output.Scenario = "unknown"
	}
	if err != nil {
		output.Value = nil
		output.Error = &normalizedError{Type: fmt.Sprintf("%T", err), Message: err.Error()}
		var sdkError *trustedrouter.Error
		if errors.As(err, &sdkError) && sdkError != nil {
			statusCode := sdkError.StatusCode
			output.Error.StatusCode = &statusCode
		}
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	_ = encoder.Encode(output)
}

func parsedURL(name string) (*url.URL, error) {
	raw, err := environment(name)
	if err != nil {
		return nil, err
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", name, err)
	}
	if parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.Port() == "" {
		return nil, fmt.Errorf("%s must be an https URL with an explicit port", name)
	}
	return parsed, nil
}

func newHTTPClient(logical, physical *url.URL, caPath string) (*http.Client, error) {
	certificate, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("read conformance CA: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certificate) {
		return nil, fmt.Errorf("conformance CA contains no PEM certificate")
	}

	dialer := &net.Dialer{}
	logicalHostname := logical.Hostname()
	physicalAddress := physical.Host
	transport := &http.Transport{
		Proxy:               nil,
		DisableKeepAlives:   true,
		ForceAttemptHTTP2:   false,
		MaxIdleConns:        0,
		MaxIdleConnsPerHost: 0,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    roots,
		},
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, splitErr := net.SplitHostPort(address)
			if splitErr != nil {
				return nil, fmt.Errorf("unexpected SDK dial address %q: %w", address, splitErr)
			}
			if port != physical.Port() {
				return nil, fmt.Errorf("refusing unexpected SDK dial port %q", port)
			}
			if !strings.EqualFold(host, logicalHostname) &&
				!strings.EqualFold(host, physical.Hostname()) &&
				!strings.EqualFold(host, "localhost") {
				return nil, fmt.Errorf("refusing unexpected SDK dial host %q", host)
			}
			return dialer.DialContext(ctx, network, physicalAddress)
		},
	}
	return &http.Client{
		Transport: transport,
		// Deliberately allow redirects on the injected client. The SDK must
		// clone it and install its own redirect isolation policy.
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return nil
		},
	}, nil
}

func parseChatRequest(bodyRaw string, options trustedrouter.CallOptions) (trustedrouter.ChatRequest, error) {
	var envelope struct {
		Model    string           `json:"model"`
		Messages []map[string]any `json:"messages"`
	}
	if err := json.Unmarshal([]byte(bodyRaw), &envelope); err != nil {
		return trustedrouter.ChatRequest{}, fmt.Errorf("parse chat request: %w", err)
	}
	var extra map[string]any
	if err := json.Unmarshal([]byte(bodyRaw), &extra); err != nil {
		return trustedrouter.ChatRequest{}, fmt.Errorf("parse chat request extensions: %w", err)
	}
	delete(extra, "model")
	delete(extra, "messages")
	delete(extra, "stream")
	return trustedrouter.ChatRequest{
		Model:       envelope.Model,
		Messages:    envelope.Messages,
		Extra:       extra,
		CallOptions: options,
	}, nil
}

func parseResponsesRequest(bodyRaw string, options trustedrouter.CallOptions) (trustedrouter.ResponsesRequest, error) {
	var envelope struct {
		Model        string  `json:"model"`
		Input        any     `json:"input"`
		Instructions *string `json:"instructions"`
	}
	if err := json.Unmarshal([]byte(bodyRaw), &envelope); err != nil {
		return trustedrouter.ResponsesRequest{}, fmt.Errorf("parse Responses request: %w", err)
	}
	var extra map[string]any
	if err := json.Unmarshal([]byte(bodyRaw), &extra); err != nil {
		return trustedrouter.ResponsesRequest{}, fmt.Errorf("parse Responses request extensions: %w", err)
	}
	delete(extra, "model")
	delete(extra, "input")
	delete(extra, "instructions")
	delete(extra, "stream")
	return trustedrouter.ResponsesRequest{
		Model:        envelope.Model,
		Input:        envelope.Input,
		Instructions: envelope.Instructions,
		Extra:        extra,
		CallOptions:  options,
	}, nil
}

func execute(
	ctx context.Context,
	client *trustedrouter.Client,
	entrypoint string,
	method string,
	path string,
	bodyRaw string,
	options trustedrouter.CallOptions,
) (any, error) {
	switch entrypoint {
	case "generic_json":
		var value json.RawMessage
		if err := client.Request(ctx, method, path, json.RawMessage(bodyRaw), &value, &options); err != nil {
			return nil, err
		}
		return value, nil
	case "chat_completions", "chat_stream_collect":
		request, err := parseChatRequest(bodyRaw, options)
		if err != nil {
			return nil, err
		}
		return client.ChatCompletions(ctx, request)
	case "responses":
		request, err := parseResponsesRequest(bodyRaw, options)
		if err != nil {
			return nil, err
		}
		return client.Responses(ctx, request)
	case "oauth_exchange":
		var body struct {
			Code                string `json:"code"`
			CodeVerifier        string `json:"code_verifier"`
			CodeChallengeMethod string `json:"code_challenge_method"`
		}
		if err := json.Unmarshal([]byte(bodyRaw), &body); err != nil {
			return nil, fmt.Errorf("parse OAuth exchange request: %w", err)
		}
		return client.ExchangeOAuthKey(ctx, trustedrouter.OAuthKeyExchangeRequest{
			Code:                body.Code,
			CodeVerifier:        body.CodeVerifier,
			CodeChallengeMethod: body.CodeChallengeMethod,
			Timeout:             options.Timeout,
		})
	default:
		return nil, fmt.Errorf("unsupported ENTRYPOINT %q", entrypoint)
	}
}

func run() (any, error) {
	logical, err := parsedURL("LOGICAL_BASE_URL")
	if err != nil {
		return nil, err
	}
	physical, err := parsedURL("PHYSICAL_ORIGIN")
	if err != nil {
		return nil, err
	}
	caPath, err := environment("CA_CERT")
	if err != nil {
		return nil, err
	}
	httpClient, err := newHTTPClient(logical, physical, caPath)
	if err != nil {
		return nil, err
	}
	defer httpClient.CloseIdleConnections()

	maxRetriesRaw, err := environment("MAX_RETRIES")
	if err != nil {
		return nil, err
	}
	maxRetries, err := strconv.Atoi(maxRetriesRaw)
	if err != nil || maxRetries < 0 {
		return nil, fmt.Errorf("MAX_RETRIES must be a non-negative integer")
	}
	timeoutRaw, err := environment("TIMEOUT_MS")
	if err != nil {
		return nil, err
	}
	timeoutMilliseconds, err := strconv.ParseInt(timeoutRaw, 10, 64)
	if err != nil || timeoutMilliseconds <= 0 || timeoutMilliseconds > int64((1<<63-1)/time.Millisecond) {
		return nil, fmt.Errorf("TIMEOUT_MS must be a positive duration")
	}
	timeout := time.Duration(timeoutMilliseconds) * time.Millisecond
	telemetryRaw, err := environment("TELEMETRY")
	if err != nil {
		return nil, err
	}
	if telemetryRaw != "0" && telemetryRaw != "1" {
		return nil, fmt.Errorf("TELEMETRY must be 0 or 1")
	}
	telemetry := telemetryRaw == "1"
	regionalFailover := false
	defaultHeadersRaw, err := environment("DEFAULT_HEADERS_JSON")
	if err != nil {
		return nil, err
	}
	defaultHeaders := map[string]string{}
	if err := json.Unmarshal([]byte(defaultHeadersRaw), &defaultHeaders); err != nil {
		return nil, fmt.Errorf("parse DEFAULT_HEADERS_JSON: %w", err)
	}

	client, err := trustedrouter.NewClient(trustedrouter.Options{
		APIKey:           "tr-conformance-key",
		BaseURL:          strings.TrimRight(logical.String(), "/"),
		ControlBaseURL:   strings.TrimRight(logical.String(), "/"),
		HTTPClient:       httpClient,
		Timeout:          &timeout,
		MaxRetries:       &maxRetries,
		RegionalFailover: &regionalFailover,
		Telemetry:        &telemetry,
		Headers:          defaultHeaders,
	})
	if err != nil {
		return nil, err
	}

	headersRaw, err := environment("HEADERS_JSON")
	if err != nil {
		return nil, err
	}
	headers := map[string]string{}
	if err := json.Unmarshal([]byte(headersRaw), &headers); err != nil {
		return nil, fmt.Errorf("parse HEADERS_JSON: %w", err)
	}
	bodyRaw, err := environment("BODY_JSON")
	if err != nil {
		return nil, err
	}
	if !json.Valid([]byte(bodyRaw)) {
		return nil, fmt.Errorf("BODY_JSON is not valid JSON")
	}
	idempotencyKey, err := environment("IDEMPOTENCY_KEY")
	if err != nil {
		return nil, err
	}
	method, err := environment("METHOD")
	if err != nil {
		return nil, err
	}
	path, err := environment("PATH")
	if err != nil {
		return nil, err
	}
	entrypoint, err := environment("ENTRYPOINT")
	if err != nil {
		return nil, err
	}
	cancelAfterRaw, err := environment("CANCEL_AFTER_MS")
	if err != nil {
		return nil, err
	}

	options := trustedrouter.CallOptions{
		ExtraHeaders:   headers,
		IdempotencyKey: idempotencyKey,
		Timeout:        &timeout,
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var cancelTimer *time.Timer
	if cancelAfterRaw != "" {
		cancelAfterMilliseconds, parseErr := strconv.ParseInt(cancelAfterRaw, 10, 64)
		if parseErr != nil || cancelAfterMilliseconds <= 0 {
			return nil, fmt.Errorf("CANCEL_AFTER_MS must be empty or a positive integer")
		}
		cancelTimer = time.AfterFunc(time.Duration(cancelAfterMilliseconds)*time.Millisecond, cancel)
		defer cancelTimer.Stop()
	}
	return execute(ctx, client, entrypoint, method, path, bodyRaw, options)
}

func main() {
	defer func() {
		if recovered := recover(); recovered != nil {
			emit("error", nil, fmt.Errorf("driver panic: %v", recovered))
		}
	}()
	value, err := run()
	if err != nil {
		emit("error", nil, err)
		return
	}
	emit("success", value, nil)
}
