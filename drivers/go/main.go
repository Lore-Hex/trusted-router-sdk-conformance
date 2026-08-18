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
			host, _, splitErr := net.SplitHostPort(address)
			if splitErr != nil {
				return nil, fmt.Errorf("unexpected SDK dial address %q: %w", address, splitErr)
			}
			if !strings.EqualFold(host, logicalHostname) {
				return nil, fmt.Errorf("refusing unexpected SDK dial host %q", host)
			}
			return dialer.DialContext(ctx, network, physicalAddress)
		},
	}
	return &http.Client{
		Transport: transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}, nil
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

	client, err := trustedrouter.NewClient(trustedrouter.Options{
		APIKey:           "tr-conformance-key",
		BaseURL:          strings.TrimRight(logical.String(), "/"),
		ControlBaseURL:   strings.TrimRight(logical.String(), "/"),
		HTTPClient:       httpClient,
		Timeout:          &timeout,
		MaxRetries:       &maxRetries,
		RegionalFailover: &regionalFailover,
		Telemetry:        &telemetry,
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

	options := &trustedrouter.CallOptions{
		ExtraHeaders:   headers,
		IdempotencyKey: idempotencyKey,
		Timeout:        &timeout,
	}
	var value json.RawMessage
	if err := client.Request(context.Background(), method, path, json.RawMessage(bodyRaw), &value, options); err != nil {
		return nil, err
	}
	return value, nil
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
