use http::Method;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use trusted_router::{CallOptions, Client, Plane};
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
    let ca = reqwest::Certificate::from_pem(&ca_pem)
        .map_err(|error| Failure::driver(format!("parse conformance CA: {error}")))?;
    let http = reqwest::Client::builder()
        .no_proxy()
        .add_root_certificate(ca)
        .resolve(logical_host, physical_address)
        .pool_max_idle_per_host(0)
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .http1_only()
        .build()
        .map_err(|error| Failure::driver(format!("build reqwest client: {error}")))?;

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

    let client = Client::builder()
        .api_key("tr-conformance-key")
        .api_base_url(logical.as_str())
        .control_base_url(logical.as_str())
        .timeout(Some(timeout))
        .max_retries(max_retries)
        .regional_failover(false)
        .telemetry(telemetry)
        .http_client(http)
        .build()
        .map_err(Failure::sdk)?;

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

    client
        .request::<Value>(Plane::Inference, method, &path, Some(body), options)
        .await
        .map_err(Failure::sdk)
}

#[tokio::main]
async fn main() {
    match run().await {
        Ok(value) => emit_success(value),
        Err(error) => emit_error(error),
    }
}
