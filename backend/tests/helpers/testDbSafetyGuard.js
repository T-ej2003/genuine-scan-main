const assert = require("assert");

const isTruthy = (value) => ["1", "true", "yes", "on"].includes(String(value || "").trim().toLowerCase());

const parseDatabaseName = (databaseUrl) => {
  try {
    const parsed = new URL(databaseUrl);
    return decodeURIComponent(parsed.pathname.replace(/^\//, ""));
  } catch {
    return "";
  }
};

const assertSafeTestDatabaseUrl = (databaseUrl, options = {}) => {
  const raw = String(databaseUrl || "").trim();
  if (!raw) throw new Error("Missing database URL");

  const parsed = new URL(raw);
  if (parsed.protocol !== "postgresql:" && parsed.protocol !== "postgres:") {
    throw new Error("Disposable DB tests only support PostgreSQL URLs.");
  }

  const databaseName = parseDatabaseName(raw).toLowerCase();
  const host = String(parsed.hostname || "").toLowerCase();
  const username = decodeURIComponent(parsed.username || "").toLowerCase();
  const urlLower = raw.toLowerCase();
  const clearlyTest = /\b(test|tests|p2|ci|tmp|temporary|integration)\b/.test(databaseName.replace(/[_-]/g, " "));
  const allowRemote = isTruthy(process.env.P2_TEST_DATABASE_ALLOW_REMOTE || process.env.INTEGRATION_TEST_DATABASE_ALLOW_REMOTE);
  const allowedHosts = new Set(["localhost", "127.0.0.1", "::1", "postgres"]);
  for (const hostValue of options.allowedHosts || []) {
    if (hostValue) allowedHosts.add(String(hostValue).toLowerCase());
  }

  const productionMarkers = [
    "prod",
    "production",
    "staging",
    "rds.amazonaws.com",
    "amazonaws.com",
    "database.azure.com",
    "supabase",
    "neon.tech",
    "railway.app",
    "render.com",
  ];

  if (!clearlyTest) {
    throw new Error(`Refusing to use database "${databaseName}". Test DB name must clearly contain test, p2, ci, tmp, temporary, or integration.`);
  }

  if (productionMarkers.some((marker) => urlLower.includes(marker))) {
    throw new Error("Refusing to use a production- or staging-looking database URL for disposable tests.");
  }

  if (
    (host.includes("mscqr") || username.includes("mscqr")) &&
    !["mscqr_p2_test", "mscqr_integration_test", "mscqr_ci_test"].some((prefix) => databaseName.startsWith(prefix))
  ) {
    throw new Error("Refusing MSCQR-named database host/user outside the approved disposable test database naming pattern.");
  }

  if (host && !allowedHosts.has(host) && !allowRemote) {
    throw new Error("Refusing non-local test database host without P2_TEST_DATABASE_ALLOW_REMOTE=true.");
  }
};

module.exports = {
  assertSafeTestDatabaseUrl,
  parseDatabaseName,
};
