const trimTrailingSlash = (value) => String(value || "").trim().replace(/\/+$/, "");
const parseBool = (value, fallback = false) => {
  const normalized = String(value || "").trim().toLowerCase();
  if (["1", "true", "yes", "on"].includes(normalized)) return true;
  if (["0", "false", "no", "off"].includes(normalized)) return false;
  return fallback;
};

const explicitSmokeBaseUrl = trimTrailingSlash(process.env.SMOKE_BASE_URL || "");
const allowLocalDefault = parseBool(process.env.SMOKE_ALLOW_LOCAL_DEFAULT, false);
if (!explicitSmokeBaseUrl && !allowLocalDefault) {
  throw new Error("SMOKE_BASE_URL is required for release/staging smoke. Use `npm run smoke:dev-local` for local default smoke.");
}

const baseUrl = trimTrailingSlash(explicitSmokeBaseUrl || process.env.PUBLIC_ADMIN_WEB_BASE_URL || process.env.WEB_APP_BASE_URL || "http://127.0.0.1:4000");
const apiBaseUrl = trimTrailingSlash(process.env.SMOKE_API_BASE_URL || `${baseUrl}/api`);

const cookieJar = new Map();

const recordSetCookies = (headers) => {
  const getter = headers?.getSetCookie;
  const rawCookies =
    typeof getter === "function"
      ? getter.call(headers)
      : headers?.get("set-cookie")
        ? [headers.get("set-cookie")]
        : [];

  for (const rawCookie of rawCookies) {
    const firstPart = String(rawCookie || "").split(";")[0] || "";
    const separatorIndex = firstPart.indexOf("=");
    if (separatorIndex <= 0) continue;
    const name = firstPart.slice(0, separatorIndex).trim();
    const value = firstPart.slice(separatorIndex + 1).trim();
    if (!name) continue;
    cookieJar.set(name, value);
  }
};

const cookieHeader = () =>
  [...cookieJar.entries()]
    .map(([name, value]) => `${name}=${value}`)
    .join("; ");

const requestJson = async (url, options = {}) => {
  const headers = {
    Accept: "application/json",
    ...(options.headers || {}),
  };

  const cookie = cookieHeader();
  if (cookie) {
    headers.Cookie = cookie;
  }

  if (options.body && !headers["Content-Type"]) {
    headers["Content-Type"] = "application/json";
  }

  let response;
  try {
    response = await fetch(url, {
      ...options,
      headers,
    });
  } catch (error) {
    throw new Error(
      `Smoke request failed for ${url}. Confirm backend/frontend target is reachable and SMOKE_BASE_URL is correct. (${error instanceof Error ? error.message : String(error)})`
    );
  }

  recordSetCookies(response.headers);

  const text = await response.text();
  const payload = text ? JSON.parse(text) : null;
  return { response, payload };
};

const ensureOk = (label, status, payload) => {
  if (status >= 200 && status < 300) return;
  throw new Error(`${label} failed with HTTP ${status}: ${JSON.stringify(payload)}`);
};

const logPass = (message) => {
  console.log(`PASS ${message}`);
};

const logSkip = (message) => {
  console.log(`SKIP ${message}`);
};

const run = async () => {
  console.log(`Smoke base: ${baseUrl}`);
  console.log(`Smoke API: ${apiBaseUrl}`);

  {
    const { response, payload } = await requestJson(`${apiBaseUrl}/health/ready`);
    ensureOk("health/ready", response.status, payload);
    logPass("ready health");
  }

  {
    const { response, payload } = await requestJson(`${apiBaseUrl}/health/live`);
    ensureOk("health/live", response.status, payload);
    logPass("live health");
  }

  if (process.env.SMOKE_VERIFY_CODE) {
    const code = encodeURIComponent(process.env.SMOKE_VERIFY_CODE);
    const { response, payload } = await requestJson(`${apiBaseUrl}/verify/${code}`);
    ensureOk("public verify", response.status, payload);
    logPass("public verify");
  } else {
    logSkip("public verify (set SMOKE_VERIFY_CODE)");
  }

  const loginEmail = String(process.env.SMOKE_LOGIN_EMAIL || "").trim();
  const loginPassword = String(process.env.SMOKE_LOGIN_PASSWORD || "").trim();

  if (!loginEmail || !loginPassword) {
    logSkip("authenticated smoke flow (set SMOKE_LOGIN_EMAIL and SMOKE_LOGIN_PASSWORD)");
    return;
  }

  let { response: loginResponse, payload: loginPayload } = await requestJson(`${apiBaseUrl}/auth/login`, {
    method: "POST",
    body: JSON.stringify({ email: loginEmail, password: loginPassword }),
  });

  ensureOk("login", loginResponse.status, loginPayload);
  logPass("login");

  if (loginPayload?.data?.auth?.sessionStage === "MFA_BOOTSTRAP") {
    const mfaCode = String(process.env.SMOKE_ADMIN_MFA_CODE || "").trim();
    if (!mfaCode) {
      throw new Error("Login entered MFA bootstrap mode. Set SMOKE_ADMIN_MFA_CODE to complete the smoke flow.");
    }

    const { response: challengeResponse, payload: challengePayload } = await requestJson(`${apiBaseUrl}/auth/mfa/challenge/begin`, {
      method: "POST",
      body: JSON.stringify({}),
    });
    ensureOk("auth mfa challenge begin", challengeResponse.status, challengePayload);

    ({ response: loginResponse, payload: loginPayload } = await requestJson(`${apiBaseUrl}/auth/mfa/challenge/complete`, {
      method: "POST",
      body: JSON.stringify({
        ticket: challengePayload?.data?.ticket,
        code: mfaCode,
      }),
    }));
    ensureOk("auth mfa challenge complete", loginResponse.status, loginPayload);
    logPass("admin MFA bootstrap completion");
  }

  {
    const { response, payload } = await requestJson(`${apiBaseUrl}/auth/me`);
    ensureOk("auth me", response.status, payload);
    logPass("current user");
  }

  {
    const { response, payload } = await requestJson(`${apiBaseUrl}/internal/release`);
    if (response.status === 401 || response.status === 403) {
      logSkip("internal release metadata (admin role required)");
    } else {
      ensureOk("internal release metadata", response.status, payload);
      logPass("internal release metadata");
    }
  }

  if (process.env.SMOKE_STEP_UP_PASSWORD) {
    const { response, payload } = await requestJson(`${apiBaseUrl}/auth/step-up/password`, {
      method: "POST",
      body: JSON.stringify({ currentPassword: process.env.SMOKE_STEP_UP_PASSWORD }),
    });
    ensureOk("password step-up", response.status, payload);
    logPass("password step-up");
  } else if (process.env.SMOKE_ADMIN_STEP_UP_CODE) {
    const { response, payload } = await requestJson(`${apiBaseUrl}/auth/mfa/step-up`, {
      method: "POST",
      body: JSON.stringify({ code: process.env.SMOKE_ADMIN_STEP_UP_CODE }),
    });
    ensureOk("admin mfa step-up", response.status, payload);
    logPass("admin MFA step-up");
  } else {
    logSkip("step-up auth (set SMOKE_STEP_UP_PASSWORD or SMOKE_ADMIN_STEP_UP_CODE)");
  }

  if (process.env.SMOKE_BATCH_PRINT_ENDPOINT && process.env.SMOKE_BATCH_PRINT_PAYLOAD_JSON) {
    const endpoint = String(process.env.SMOKE_BATCH_PRINT_ENDPOINT).trim();
    const payload = JSON.parse(process.env.SMOKE_BATCH_PRINT_PAYLOAD_JSON);
    const { response, payload: result } = await requestJson(
      endpoint.startsWith("http") ? endpoint : `${apiBaseUrl}${endpoint}`,
      {
        method: "POST",
        body: JSON.stringify(payload),
      }
    );
    ensureOk("batch print smoke", response.status, result);
    logPass("batch print smoke");
  } else {
    logSkip("batch print smoke (set SMOKE_BATCH_PRINT_ENDPOINT and SMOKE_BATCH_PRINT_PAYLOAD_JSON)");
  }

  if (process.env.SMOKE_INCIDENT_ENDPOINT && process.env.SMOKE_INCIDENT_PAYLOAD_JSON) {
    const endpoint = String(process.env.SMOKE_INCIDENT_ENDPOINT).trim();
    const payload = JSON.parse(process.env.SMOKE_INCIDENT_PAYLOAD_JSON);
    const { response, payload: result } = await requestJson(
      endpoint.startsWith("http") ? endpoint : `${apiBaseUrl}${endpoint}`,
      {
        method: "POST",
        body: JSON.stringify(payload),
      }
    );
    ensureOk("incident create smoke", response.status, result);
    logPass("incident create smoke");
  } else {
    logSkip("incident create smoke (set SMOKE_INCIDENT_ENDPOINT and SMOKE_INCIDENT_PAYLOAD_JSON)");
  }

  if (process.env.SMOKE_EVIDENCE_URL || process.env.SMOKE_EVIDENCE_PATH) {
    const endpoint = trimTrailingSlash(process.env.SMOKE_EVIDENCE_URL || "");
    const path = String(process.env.SMOKE_EVIDENCE_PATH || "").trim();
    const url = endpoint || `${apiBaseUrl}${path}`;
    const cookie = cookieHeader();
    const response = await fetch(url, {
      headers: cookie ? { Cookie: cookie } : undefined,
    });
    if (!response.ok) {
      throw new Error(`evidence smoke failed with HTTP ${response.status}`);
    }
    logPass("evidence retrieval smoke");
  } else {
    logSkip("evidence retrieval smoke (set SMOKE_EVIDENCE_URL or SMOKE_EVIDENCE_PATH)");
  }
};

run().catch((error) => {
  console.error(error instanceof Error ? error.message : error);
  process.exit(1);
});
