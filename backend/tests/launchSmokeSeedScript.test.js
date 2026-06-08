const assert = require("assert");
const { spawnSync } = require("child_process");
const path = require("path");

const backendRoot = path.resolve(__dirname, "..");
const scriptPath = path.join(backendRoot, "scripts", "seed-launch-smoke-users.js");
const seed = require(scriptPath);

const runScript = (extraEnv = {}) =>
  spawnSync(process.execPath, [scriptPath], {
    cwd: backendRoot,
    env: {
      ...process.env,
      DATABASE_URL: "",
      LAUNCH_SMOKE_SEED_ENABLED: "",
      LAUNCH_SMOKE_CONFIRM: "",
      LAUNCH_SMOKE_MFA_CONFIRM: "",
      LAUNCH_SMOKE_REFRESH_ADMIN_MFA: "",
      LAUNCH_SMOKE_SUPERADMIN_EMAIL: "",
      LAUNCH_SMOKE_SUPERADMIN_PASSWORD: "",
      LAUNCH_SMOKE_LICENSEE_ADMIN_EMAIL: "",
      LAUNCH_SMOKE_LICENSEE_ADMIN_PASSWORD: "",
      LAUNCH_SMOKE_MANUFACTURER_EMAIL: "",
      LAUNCH_SMOKE_MANUFACTURER_PASSWORD: "",
      ...extraEnv,
    },
    encoding: "utf8",
  });

const parseJson = (result) => {
  assert.strictEqual(result.stderr, "", `script wrote unexpected stderr: ${result.stderr}`);
  return JSON.parse(result.stdout);
};

const disabled = runScript();
assert.strictEqual(disabled.status, 1, "seed must refuse when not explicitly enabled");
const disabledPayload = parseJson(disabled);
assert.strictEqual(disabledPayload.ok, false);
assert.match(disabledPayload.diagnostic, /LAUNCH_SMOKE_SEED_ENABLED/i);
assert.doesNotMatch(disabled.stdout, /postgres:\/\/|postgresql:\/\/|DATABASE_URL|passwordHash|secret/i);

const missingConfirm = runScript({
  LAUNCH_SMOKE_SEED_ENABLED: "true",
  NODE_ENV: "staging",
  DATABASE_URL: "redacted-db-url-present",
});
assert.strictEqual(missingConfirm.status, 1, "seed must refuse without confirmation phrase");
const missingConfirmPayload = parseJson(missingConfirm);
assert.strictEqual(missingConfirmPayload.ok, false);
assert.match(missingConfirmPayload.diagnostic, /LAUNCH_SMOKE_CONFIRM/i);
assert.doesNotMatch(missingConfirm.stdout, /postgres:\/\/|postgresql:\/\/|user:password|passwordHash/i);

const password = seed.generateStrongPassword();
assert.ok(password.length >= seed.PASSWORD_LENGTH, "generated password should meet configured length");
assert.match(password, /[a-z]/, "generated password should include lowercase");
assert.match(password, /[A-Z]/, "generated password should include uppercase");
assert.match(password, /\d/, "generated password should include digits");
assert.match(password, /[^A-Za-z0-9]/, "generated password should include symbols");

const credentials = seed.buildCredentialOutput(
  [
    {
      key: "superAdmin",
      email: "launch-platform@staging.example",
      password: "RedactionSentinelValue123!",
      passwordSource: "generated",
    },
  ],
  true
);
assert.strictEqual(credentials.superAdmin.password, "[redacted]");
assert.doesNotMatch(JSON.stringify(credentials), /RedactionSentinel/i, "redacted credential output must not include passwords");

const redactedEvidence = seed.buildRedactedEvidence({
  environment: "staging",
  licenseePrefix: "LSMK",
  refreshAdminMfa: true,
  userResults: [
    {
      key: "superAdmin",
      email: "launch-platform@staging.example",
      role: "SUPER_ADMIN",
      userId: "user-1",
      action: "created",
      adminMfaFreshened: true,
    },
  ],
  auditId: "audit-1",
});
assert.doesNotMatch(JSON.stringify(redactedEvidence), /launch-platform@staging\.example/);
assert.match(JSON.stringify(redactedEvidence), /\*\*\*/);

assert.throws(
  () =>
    seed.readConfig({
      LAUNCH_SMOKE_SEED_ENABLED: "true",
      NODE_ENV: "production",
      LAUNCH_SMOKE_CONFIRM: seed.CONFIRMATION_PHRASE,
      DATABASE_URL: "redacted-db-url-present",
      LAUNCH_SMOKE_REFRESH_ADMIN_MFA: "true",
      LAUNCH_SMOKE_SUPERADMIN_EMAIL: "platform@staging.example",
      LAUNCH_SMOKE_LICENSEE_ADMIN_EMAIL: "licensee@staging.example",
      LAUNCH_SMOKE_MANUFACTURER_EMAIL: "manufacturer@staging.example",
    }),
  /LAUNCH_SMOKE_MFA_CONFIRM/,
  "MFA freshness must require its own confirmation phrase"
);

console.log("launch smoke seed script tests passed");
