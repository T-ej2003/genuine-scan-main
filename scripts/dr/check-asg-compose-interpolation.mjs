#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const root = process.cwd();
const runDockerComposeConfig = process.argv.includes("--docker-compose-config");

const read = (repoPath) => fs.readFileSync(path.join(root, repoPath), "utf8");
const fail = (message) => {
  console.error(message);
  process.exit(1);
};

const composePath = "docker-compose.asg-web.yml";
const manifestPath = "documents/ops/aws-asg-web-ssm-parameter-manifest.json";
const bootstrapPath = "scripts/dr/bootstrap-asg-web-node.sh";

const compose = read(composePath);
const manifest = JSON.parse(read(manifestPath));
const bootstrap = read(bootstrapPath);

const collectSectionKeys = (section = {}) =>
  new Set([
    ...(section.requiredFromSsm || []),
    ...(section.optionalFromSsm || []),
    ...Object.keys(section.forced || {}),
  ]);

const rootKeys = collectSectionKeys(manifest.rootEnv);
const backendKeys = collectSectionKeys(manifest.backendEnv);
const composeEnvKeys = new Set([...rootKeys, ...backendKeys]);

const requiredInterpolationVars = new Set();
const requiredInterpolationPattern = /\$\{([A-Za-z_][A-Za-z0-9_]*)(?::\?|\?)[^}]*\}/g;
let match;
while ((match = requiredInterpolationPattern.exec(compose)) !== null) {
  requiredInterpolationVars.add(match[1]);
}

for (const variable of requiredInterpolationVars) {
  if (!composeEnvKeys.has(variable)) {
    fail(`${composePath} requires ${variable} during interpolation, but it is not rendered into the ASG Compose interpolation env.`);
  }
}

for (const variable of ["QR_SIGN_PRIVATE_KEY", "QR_SIGN_PUBLIC_KEY", "QR_SIGN_ACTIVE_KEY_VERSION"]) {
  if (!backendKeys.has(variable)) {
    fail(`${manifestPath} must keep ${variable} in backendEnv for the backend container.`);
  }
  if (!composeEnvKeys.has(variable)) {
    fail(`${manifestPath} must make ${variable} available to Compose interpolation.`);
  }
}

if (!/const composeEnv = new Map\(\[\.\.\.rootEnv\.entries\(\), \.\.\.backendEnv\.entries\(\)\]\)/.test(bootstrap)) {
  fail(`${bootstrapPath} must render a Compose interpolation env from rootEnv plus backendEnv.`);
}
if (!/writeEnv\(rootEnvPath, "composeRootEnv", composeEnv\)/.test(bootstrap)) {
  fail(`${bootstrapPath} must persist project .env as a Compose interpolation env for post-bootstrap diagnostics.`);
}
if (!/docker compose --env-file "\$compose_env_path" -f docker-compose\.asg-web\.yml/.test(bootstrap)) {
  fail(`${bootstrapPath} must pass the generated Compose interpolation env with docker compose --env-file.`);
}
if (!/required SSM parameter is empty/.test(bootstrap)) {
  fail(`${bootstrapPath} must fail before Compose when a required SSM parameter exists but is empty.`);
}
if (/console\.log\([^)]*values\.get|console\.error\([^)]*values\.get/.test(bootstrap)) {
  fail(`${bootstrapPath} must not print SSM parameter values.`);
}

const dummyValueFor = (key) => {
  if (key === "AWS_REGION" || key === "OBJECT_STORAGE_REGION") return "ap-south-1";
  if (key === "REDIS_URL") return "rediss://regional-elasticache:6379/0";
  if (key === "OBJECT_STORAGE_BUCKET") return "mscqr-dummy-artifacts";
  if (key === "BACKEND_PORT") return "4000";
  if (key === "FRONTEND_PORT") return "80";
  if (key === "FRONTEND_SSL_PORT") return "443";
  if (key === "QR_SIGN_PRIVATE_KEY") return "ZHVtbXktcHJpdmF0ZS1rZXk=";
  if (key === "QR_SIGN_PUBLIC_KEY") return "ZHVtbXktcHVibGljLWtleQ==";
  if (key === "QR_SIGN_ACTIVE_KEY_VERSION") return "v1";
  if (key === "COOKIE_SECURE" || key.endsWith("_ENABLED")) return "true";
  if (key.startsWith("PUBLIC_") || key === "WEB_APP_BASE_URL" || key === "CORS_ORIGIN") return "https://dr-mumbai.mscqr.com";
  if (key === "DATABASE_URL") return "postgresql://user:pass@db.example.com:5432/mscqr";
  if (key === "SMTP_HOST") return "smtp.example.com";
  if (key === "SMTP_USER" || key === "SMTP_FROM" || key === "SUPER_ADMIN_EMAIL") return "ops@example.com";
  if (key === "SMTP_PASS") return "dummy-smtp-pass";
  return "dummy";
};

const writeEnv = (filePath, keys) => {
  const lines = [...keys].sort().map((key) => `${key}=${dummyValueFor(key)}`);
  fs.writeFileSync(filePath, `${lines.join("\n")}\n`, { mode: 0o600 });
};

if (runDockerComposeConfig) {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-asg-compose-check-"));
  try {
    fs.writeFileSync(path.join(tmpDir, "docker-compose.asg-web.yml"), compose);
    fs.mkdirSync(path.join(tmpDir, "backend"), { recursive: true });
    writeEnv(path.join(tmpDir, ".env"), composeEnvKeys);
    writeEnv(path.join(tmpDir, "compose.env"), composeEnvKeys);
    writeEnv(path.join(tmpDir, "backend", ".env"), backendKeys);
    execFileSync("docker", ["compose", "--env-file", "compose.env", "-f", "docker-compose.asg-web.yml", "config", "--quiet"], {
      cwd: tmpDir,
      stdio: "pipe",
    });
    execFileSync("docker", ["compose", "-f", "docker-compose.asg-web.yml", "config", "--quiet"], {
      cwd: tmpDir,
      stdio: "pipe",
    });
  } catch (error) {
    const stderr = error?.stderr ? String(error.stderr) : "";
    fail(`docker compose config failed for dummy ASG Compose interpolation env.\n${stderr}`.trim());
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

console.log("ASG Compose interpolation check passed.");
