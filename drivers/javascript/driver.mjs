#!/usr/bin/env node
/** Black-box adapter for the checked-out JavaScript SDK. */

import path from "node:path";
import { readFile } from "node:fs/promises";
import { pathToFileURL } from "node:url";

function env(name) {
  const value = process.env[`TR_CONFORMANCE_${name}`];
  if (value === undefined) throw new Error(`missing TR_CONFORMANCE_${name}`);
  return value;
}

function emit(outcome, value = null, error = null) {
  const errorDetail = outcome === "error" ? {
    type: error?.constructor?.name ?? "UnknownError",
    message: (typeof error?.message === "string" && error.message) ||
      error?.constructor?.name || String(error),
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
  const sdkRoot = env("SDK_ROOT");
  const packagePath = path.join(sdkRoot, "package.json");
  const packageJson = JSON.parse(await readFile(packagePath, "utf8"));
  const rootExport = packageJson.exports?.["."];
  const entry = [
    typeof rootExport === "string" ? rootExport : undefined,
    rootExport?.import,
    rootExport?.default,
    packageJson.main,
  ].find((value) => typeof value === "string" && value.length > 0);
  if (entry === undefined) {
    throw new Error(
      `Cannot resolve SDK entry from ${packagePath}: checked exports["."] ` +
      `(string, "import", "default") and "main"; expected a non-empty string`,
    );
  }
  const moduleUrl = pathToFileURL(path.resolve(sdkRoot, entry));
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
    headers: JSON.parse(env("DEFAULT_HEADERS_JSON")),
    maxRetries: Number(env("MAX_RETRIES")),
    regionalFailover: false,
    regionalAffinity: false,
    telemetry: env("TELEMETRY") === "1",
  });

  const body = JSON.parse(env("BODY_JSON"));
  const extraHeaders = JSON.parse(env("HEADERS_JSON"));
  const idempotencyKey = env("IDEMPOTENCY_KEY") || null;
  const timeout = Number(env("TIMEOUT_MS"));
  const cancelAfter = env("CANCEL_AFTER_MS");
  const controller = cancelAfter ? new AbortController() : null;

  const execute = () => {
    switch (env("ENTRYPOINT")) {
      case "generic_json":
        return client.request(env("METHOD"), env("PATH"), {
          body,
          extraHeaders,
          idempotencyKey,
          timeout,
          signal: controller?.signal,
        });
      case "chat_completions":
      case "chat_stream_collect":
        return client.chatCompletions({
          ...body,
          extraHeaders,
          idempotencyKey,
          timeout,
        });
      case "responses":
        return client.responses({
          ...body,
          extraHeaders,
          idempotencyKey,
          timeout,
        });
      case "oauth_exchange":
        return client.exchangeOAuthKey({
          code: body.code,
          codeVerifier: body.code_verifier ?? null,
          codeChallengeMethod: body.code_challenge_method ?? null,
          timeout,
        });
      default:
        throw new Error(`unsupported conformance entrypoint ${env("ENTRYPOINT")}`);
    }
  };

  let cancelTimer = null;
  if (controller !== null) {
    cancelTimer = setTimeout(() => controller.abort(), Number(cancelAfter));
  }
  try {
    emit("success", await execute());
  } catch (error) {
    emit("error", null, error);
  } finally {
    if (cancelTimer !== null) clearTimeout(cancelTimer);
  }
}

main().catch((error) => emit("error", null, error));
