use futures_util::StreamExt;
use http::Method;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use trusted_router::{
    CallOptions, ChatRequest, Client, OAuthKeyExchangeRequest, Plane, ResponsesRequest,
};
use url::Url;

struct Failure {
    kind: String,
    message: String,
    status_code: Option<u16>,
}

impl Failure {
    fn driver(message: impl Into<String>) -> Self {
        Self {
            kind: "DriverError".to_owned(),
            message: message.into(),
            status_code: None,
        }
    }

    fn sdk(error: trusted_router::Error) -> Self {
        Self {
            kind: format!("trusted_router::{:?}", error.kind()),
            message: error.to_string(),
            status_code: error.status_code(),
        }
    }
}

fn environment(name: &str) -> Result<String, Failure> {
    let key = format!("TR_CONFORMANCE_{name}");
    std::env::var(&key).map_err(|_| Failure::driver(format!("missing {key}")))
}

fn scenario() -> String {
    std::env::var("TR_CONFORMANCE_SCENARIO").unwrap_or_else(|_| "unknown".to_owned())
}

fn emit_success(value: Value) {
    println!(
        "{}",
        json!({
            "protocol_version": 1,
            "sdk": "rust",
            "scenario": scenario(),
            "outcome": "success",
            "value": value,
            "error": Value::Null,
        })
    );
}

fn emit_error(error: Failure) {
    println!(
        "{}",
        json!({
            "protocol_version": 1,
            "sdk": "rust",
            "scenario": scenario(),
            "outcome": "error",
            "value": Value::Null,
            "error": {
                "type": error.kind,
                "message": error.message,
                "status_code": error.status_code,
            },
        })
    );
}

fn parse_url(name: &str) -> Result<Url, Failure> {
    let value = environment(name)?;
    let parsed =
        Url::parse(&value).map_err(|error| Failure::driver(format!("invalid {name}: {error}")))?;
    if parsed.scheme() != "https" || parsed.host_str().is_none() || parsed.port().is_none() {
        return Err(Failure::driver(format!(
            "{name} must be an https URL with an explicit port"
        )));
    }
    Ok(parsed)
}

async fn run() -> Result<Value, Failure> {
    let logical = parse_url("LOGICAL_BASE_URL")?;
    let physical = parse_url("PHYSICAL_ORIGIN")?;
    let logical_host = logical
        .host_str()
        .ok_or_else(|| Failure::driver("logical base URL has no host"))?;
    let physical_ip: IpAddr = physical
        .host_str()
        .ok_or_else(|| Failure::driver("physical origin has no host"))?
        .parse()
        .map_err(|error| Failure::driver(format!("physical origin host is not an IP: {error}")))?;
    let physical_address = SocketAddr::new(
        physical_ip,
        physical
            .port()
            .ok_or_else(|| Failure::driver("physical origin has no port"))?,
    );

    let ca_path = environment("CA_CERT")?;
    let ca_pem = std::fs::read(&ca_path)
        .map_err(|error| Failure::driver(format!("read conformance CA: {error}")))?;

    let max_retries: usize = environment("MAX_RETRIES")?
        .parse()
        .map_err(|error| Failure::driver(format!("invalid MAX_RETRIES: {error}")))?;
    let timeout_ms: u64 = environment("TIMEOUT_MS")?
        .parse()
        .map_err(|error| Failure::driver(format!("invalid TIMEOUT_MS: {error}")))?;
    if timeout_ms == 0 {
        return Err(Failure::driver("TIMEOUT_MS must be positive"));
    }
    let timeout = Duration::from_millis(timeout_ms);
    let telemetry = match environment("TELEMETRY")?.as_str() {
        "0" => false,
        "1" => true,
        _ => return Err(Failure::driver("TELEMETRY must be 0 or 1")),
    };

    let default_headers: BTreeMap<String, String> =
        serde_json::from_str(&environment("DEFAULT_HEADERS_JSON")?)
            .map_err(|error| Failure::driver(format!("parse DEFAULT_HEADERS_JSON: {error}")))?;
    let mut builder = Client::builder()
        .api_key("tr-conformance-key")
        .api_base_url(logical.as_str())
        .control_base_url(logical.as_str())
        .timeout(Some(timeout))
        .max_retries(max_retries)
        .regional_failover(false)
        .telemetry(telemetry)
        .root_certificate_pem(ca_pem)
        .resolve_hostname(logical_host.to_owned(), physical_address);
    for (name, value) in default_headers {
        builder = builder.header(name, value);
    }
    let client = builder.build().map_err(Failure::sdk)?;

    let body: Value = serde_json::from_str(&environment("BODY_JSON")?)
        .map_err(|error| Failure::driver(format!("parse BODY_JSON: {error}")))?;
    let headers: BTreeMap<String, String> = serde_json::from_str(&environment("HEADERS_JSON")?)
        .map_err(|error| Failure::driver(format!("parse HEADERS_JSON: {error}")))?;
    let method: Method = environment("METHOD")?
        .parse()
        .map_err(|error| Failure::driver(format!("invalid METHOD: {error}")))?;
    let path = environment("PATH")?;
    let idempotency_key = environment("IDEMPOTENCY_KEY")?;
    let options = CallOptions {
        idempotency_key: (!idempotency_key.is_empty()).then_some(idempotency_key),
        timeout: Some(timeout),
        headers,
        ..CallOptions::default()
    };

    let entrypoint = environment("ENTRYPOINT")?;
    let operation = execute(&client, &entrypoint, method, &path, body, options);
    let cancel_after = environment("CANCEL_AFTER_MS")?;
    if cancel_after.is_empty() {
        operation.await
    } else {
        let cancel_after_ms: u64 = cancel_after
            .parse()
            .map_err(|error| Failure::driver(format!("invalid CANCEL_AFTER_MS: {error}")))?;
        if cancel_after_ms == 0 {
            return Err(Failure::driver("CANCEL_AFTER_MS must be positive"));
        }
        tokio::select! {
            result = operation => result,
            () = tokio::time::sleep(Duration::from_millis(cancel_after_ms)) => {
                Err(Failure::driver("caller cancelled the SDK operation"))
            }
        }
    }
}

fn object_body(body: Value, entrypoint: &str) -> Result<serde_json::Map<String, Value>, Failure> {
    body.as_object()
        .cloned()
        .ok_or_else(|| Failure::driver(format!("{entrypoint} body must be a JSON object")))
}

fn chat_request(body: Value, options: CallOptions) -> Result<ChatRequest, Failure> {
    let mut object = object_body(body, "chat")?;
    let model = object
        .remove("model")
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_default();
    let messages = object
        .remove("messages")
        .and_then(|value| value.as_array().cloned())
        .unwrap_or_default();
    object.remove("stream");
    Ok(ChatRequest {
        model,
        messages,
        models: Vec::new(),
        tools: Vec::new(),
        provider: None,
        metadata: None,
        depth: None,
        extra: object.into_iter().collect(),
        call_options: options,
    })
}

fn responses_request(body: Value, options: CallOptions) -> Result<ResponsesRequest, Failure> {
    let mut object = object_body(body, "responses")?;
    let model = object
        .remove("model")
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_default();
    let input = object.remove("input").unwrap_or(Value::Null);
    let instructions = object
        .remove("instructions")
        .and_then(|value| value.as_str().map(str::to_owned));
    let store = object
        .remove("store")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    object.remove("stream");
    Ok(ResponsesRequest {
        model,
        input,
        instructions,
        models: Vec::new(),
        tools: Vec::new(),
        provider: None,
        metadata: None,
        store,
        extra: object.into_iter().collect(),
        call_options: options,
    })
}

async fn execute(
    client: &Client,
    entrypoint: &str,
    method: Method,
    path: &str,
    body: Value,
    options: CallOptions,
) -> Result<Value, Failure> {
    match entrypoint {
        "generic_json" => client
            .request::<Value>(Plane::Inference, method, path, Some(body), options)
            .await
            .map_err(Failure::sdk),
        "chat_completions" => {
            let response = client
                .chat_completions(chat_request(body, options)?)
                .await
                .map_err(Failure::sdk)?;
            serde_json::to_value(response)
                .map_err(|error| Failure::driver(format!("serialize chat response: {error}")))
        }
        "chat_stream_collect" => {
            let mut stream = client
                .chat_completions_stream(chat_request(body, options)?)
                .await
                .map_err(Failure::sdk)?;
            let mut chunks = Vec::new();
            while let Some(chunk) = stream.next().await {
                chunks.push(chunk.map_err(Failure::sdk)?);
            }
            Ok(Value::Array(chunks))
        }
        "responses" => {
            let response = client
                .responses(responses_request(body, options)?)
                .await
                .map_err(Failure::sdk)?;
            serde_json::to_value(response)
                .map_err(|error| Failure::driver(format!("serialize Responses result: {error}")))
        }
        "oauth_exchange" => {
            let mut object = object_body(body, "oauth_exchange")?;
            let code = object
                .remove("code")
                .and_then(|value| value.as_str().map(str::to_owned))
                .unwrap_or_default();
            let code_verifier = object
                .remove("code_verifier")
                .and_then(|value| value.as_str().map(str::to_owned));
            let code_challenge_method = object
                .remove("code_challenge_method")
                .and_then(|value| value.as_str().map(str::to_owned));
            let response = client
                .exchange_oauth_key(OAuthKeyExchangeRequest {
                    code,
                    code_verifier,
                    code_challenge_method,
                    call_options: options,
                })
                .await
                .map_err(Failure::sdk)?;
            serde_json::to_value(response)
                .map_err(|error| Failure::driver(format!("serialize OAuth response: {error}")))
        }
        _ => Err(Failure::driver(format!(
            "unsupported ENTRYPOINT {entrypoint:?}"
        ))),
    }
}

#[tokio::main]
async fn main() {
    match run().await {
        Ok(value) => emit_success(value),
        Err(error) => emit_error(error),
    }
}
