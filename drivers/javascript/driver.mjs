#!/usr/bin/env node
/** Black-box adapter for the checked-out JavaScript SDK. */

import path from "node:path";
import { pathToFileURL } from "node:url";

function env(name) {
  const value = process.env[`TR_CONFORMANCE_${name}`];
  if (value === undefined) throw new Error(`missing TR_CONFORMANCE_${name}`);
  return value;
}

function emit(outcome, value = null, error = null) {
  const errorDetail = outcome === "error" ? {
    type: error?.constructor?.name ?? "UnknownError",
    message: typeof error?.message === "string" ? error.message : String(error),
  } : null;
  if (errorDetail !== null && Number.isInteger(error?.statusCode)) {
    errorDetail.status_code = error.statusCode;
  }
  process.stdout.write(`${JSON.stringify({
    protocol_version: 1,
    sdk: "javascript",
    scenario: process.env.TR_CONFORMANCE_SCENARIO ?? "unknown",
    outcome,
    value: outcome === "success" ? value : null,
    error: errorDetail,
  })}\n`);
}

async function main() {
  const moduleUrl = pathToFileURL(path.join(env("SDK_ROOT"), "src", "index.js"));
  const { TrustedRouter } = await import(moduleUrl.href);
  const physical = new URL(env("PHYSICAL_ORIGIN"));
  const fetchImpl = async (input, init) => {
    const url = new URL(typeof input === "string" ? input : input.url);
    url.protocol = physical.protocol;
    url.hostname = physical.hostname;
    url.port = physical.port;
    return globalThis.fetch(url, init);
  };
  const client = new TrustedRouter({
    apiKey: "tr-conformance-key",
    baseUrl: env("LOGICAL_BASE_URL"),
    controlBaseUrl: env("LOGICAL_BASE_URL"),
    fetchImpl,
    maxRetries: Number(env("MAX_RETRIES")),
    regionalFailover: false,
    regionalAffinity: false,
  });
  const idempotencyKey = env("IDEMPOTENCY_KEY") || null;
  try {
    const value = await client.request(env("METHOD"), env("PATH"), {
      body: JSON.parse(env("BODY_JSON")),
      extraHeaders: JSON.parse(env("HEADERS_JSON")),
      idempotencyKey,
      timeout: Number(env("TIMEOUT_MS")),
    });
    emit("success", value);
  } catch (error) {
    emit("error", null, error);
  }
}

main().catch((error) => emit("error", null, error));
