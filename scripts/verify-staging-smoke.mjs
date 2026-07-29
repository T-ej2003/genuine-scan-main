import { spawnSync } from "node:child_process";

const env = process.env;
const base = String(env.STAGING_SMOKE_BASE_URL || "").trim();
const api = String(env.STAGING_SMOKE_API_BASE_URL || "").trim();
const enabled = String(env.STAGING_SMOKE_ENABLED || "").trim();
const productionHosts = new Set(["mscqr.com", "www.mscqr.com"]);

export function stagingSmokeMode(values = env) {
  const value = String(values.STAGING_SMOKE_ENABLED || "").trim();
  const urls = [values.STAGING_SMOKE_BASE_URL, values.STAGING_SMOKE_API_BASE_URL].filter(Boolean);
  for (const raw of urls) {
    const url = new URL(raw);
    if (url.protocol !== "https:" || productionHosts.has(url.hostname)) throw new Error("Staging smoke configuration contains a prohibited production or non-HTTPS target.");
  }
  if (value === "false") return "staging_not_provisioned";
  const configuredBase = String(values.STAGING_SMOKE_BASE_URL || "").trim();
  const configuredApi = String(values.STAGING_SMOKE_API_BASE_URL || "").trim();
  if (value !== "true" || !configuredBase || !configuredApi || !values.STAGING_SMOKE_LOGIN_EMAIL || !values.STAGING_SMOKE_LOGIN_PASSWORD) throw new Error("Live staging smoke requires enabled staging URLs and dedicated credentials.");
  const baseUrl = new URL(configuredBase); const apiUrl = new URL(configuredApi);
  if (baseUrl.origin !== apiUrl.origin) throw new Error("Staging base and API origins must match.");
  return "live_staging";
}

export async function verifyStagingIdentity(values = env, fetchImpl = globalThis.fetch) {
  stagingSmokeMode(values);
  const apiUrl = new URL(String(values.STAGING_SMOKE_API_BASE_URL));
  const response = await fetchImpl(new URL(`${apiUrl.pathname.replace(/\/$/, "")}/health/ready`, apiUrl.origin), {
    headers: { accept: "application/json" }, signal: AbortSignal.timeout(10_000),
  });
  let payload;
  try { payload = await response.json(); } catch { throw new Error("Staging identity response is not valid JSON."); }
  if (!response.ok || payload?.release?.environment !== "staging") throw new Error("Staging identity preflight did not report release.environment=staging.");
  return true;
}

if (process.argv[1] === new URL(import.meta.url).pathname) {
  const mode = stagingSmokeMode();
  if (mode === "staging_not_provisioned") {
    console.log(JSON.stringify({ status: mode, network: "not_attempted" }));
  } else {
    await verifyStagingIdentity();
    const result = spawnSync("node", ["scripts/smoke-release.mjs"], { stdio: "inherit", env: { ...env, SMOKE_BASE_URL: base, SMOKE_API_BASE_URL: api, SMOKE_LOGIN_EMAIL: env.STAGING_SMOKE_LOGIN_EMAIL, SMOKE_LOGIN_PASSWORD: env.STAGING_SMOKE_LOGIN_PASSWORD, SMOKE_VERIFY_CODE: env.STAGING_SMOKE_VERIFY_CODE || "", SMOKE_ALLOW_LOCAL_DEFAULT: "false" } });
    process.exit(result.status ?? 1);
  }
}
