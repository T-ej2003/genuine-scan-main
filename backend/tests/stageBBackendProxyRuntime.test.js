const assert = require("node:assert/strict");
const fs = require("node:fs");
const http = require("node:http");
const path = require("node:path");

const candidate = JSON.parse(fs.readFileSync(path.join(__dirname, "../../infra/aws/terraform/production-green-stage-b/task-definitions/green-backend-candidate.json"), "utf8"));
const renderedEnvironment = Object.fromEntries(candidate.containerDefinitions[0].environment.map(({ name, value }) => [name, value]));
const placeholderValues = {
  "{{BACKEND_CLIENT_IP_TRUST_MODE}}": "cloudfront-alb",
  "{{BACKEND_CLIENT_IP_TRUSTED_ALB_CIDRS}}": "10.10.0.0/24",
  "{{BACKEND_CLIENT_IP_TRUSTED_CLOUDFRONT_CIDRS}}": "198.51.100.0/24",
};
for (const [name, value] of Object.entries(renderedEnvironment)) {
  renderedEnvironment[name] = placeholderValues[value] || value;
}

const envKeys = [
  "NODE_ENV", "REQUIRE_REDIS_FOR_SHARED_STATE", "DATABASE_URL", "PREAUTH_DATABASE_URL",
  "AUTHENTICATED_APP_DATABASE_URL", "JWT_SECRET", "IP_HASH_SALT_CURRENT",
  "CLIENT_IP_TRUST_MODE", "CLIENT_IP_TRUSTED_ALB_CIDRS", "CLIENT_IP_TRUSTED_CLOUDFRONT_CIDRS",
  "CLIENT_IP_TRUSTED_NGINX_CIDRS", "MSCQR_PRODUCTION_GREEN_APPLICATION_CANARY",
];
const savedEnvironment = Object.fromEntries(envKeys.map((name) => [name, process.env[name]]));
const restoreEnvironment = () => {
  for (const [name, value] of Object.entries(savedEnvironment)) {
    if (value === undefined) delete process.env[name];
    else process.env[name] = value;
  }
};
const request = ({ remoteAddress, forwardedFor = "", forwardedProto = "" }) => ({
  socket: { remoteAddress },
  get: (name) => ({
    "x-forwarded-for": forwardedFor,
    "x-forwarded-proto": forwardedProto,
  }[name.toLowerCase()] || ""),
});

(async () => {
  Object.assign(process.env, {
    NODE_ENV: "production",
    REQUIRE_REDIS_FOR_SHARED_STATE: "false",
    DATABASE_URL: "postgresql://stage_b_runtime@127.0.0.1:1/stage_b?connect_timeout=1",
    PREAUTH_DATABASE_URL: "postgresql://stage_b_preauth@127.0.0.1:1/stage_b?connect_timeout=1",
    AUTHENTICATED_APP_DATABASE_URL: "postgresql://stage_b_app@127.0.0.1:1/stage_b?connect_timeout=1",
    JWT_SECRET: "stage-b-runtime-test-secret",
    IP_HASH_SALT_CURRENT: "stage-b-runtime-test-salt",
    ...renderedEnvironment,
  });

  const { createBackendApp } = require("../dist/app");
  const { getClientIpTrustConfig, resolveClientIp, resolveExternalProtocol } = require("../dist/utils/clientIp");
  const config = getClientIpTrustConfig();
  assert.equal(config.mode, "cloudfront-alb");

  const app = createBackendApp();
  const server = http.createServer(app);
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const trusted = request({
      remoteAddress: "10.10.0.10",
      forwardedFor: "203.0.113.10, 198.51.100.10",
      forwardedProto: "https",
    });
    assert.equal(resolveClientIp(trusted, config), "203.0.113.10");
    assert.equal(resolveExternalProtocol(trusted, config), "https");
    assert.throws(
      () => resolveClientIp(request({ remoteAddress: "10.10.0.10", forwardedFor: "spoofed, 198.51.100.10" }), config),
      /CLIENT_IP_PROXY_CHAIN_DENIED/,
    );
    assert.throws(
      () => resolveClientIp(request({ remoteAddress: "10.11.0.10", forwardedFor: "203.0.113.10, 198.51.100.10" }), config),
      /CLIENT_IP_PROXY_CHAIN_DENIED/,
    );
    assert.equal(
      resolveExternalProtocol(request({ remoteAddress: "10.10.0.10", forwardedFor: "203.0.113.10, 198.51.100.10", forwardedProto: "https,http" }), config),
      "http",
    );
    assert.equal(app.get("trust proxy"), false);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
  console.log("Stage-B backend candidate runtime proxy tests passed");
})().finally(restoreEnvironment).catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
