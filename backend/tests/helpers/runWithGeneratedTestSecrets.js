const { randomBytes } = require("crypto");
const { spawnSync } = require("child_process");

const command = process.argv.slice(2).join(" ");

if (!command) {
  console.error("Usage: node tests/helpers/runWithGeneratedTestSecrets.js <command>");
  process.exit(2);
}

const randomHex = () => randomBytes(32).toString("hex");
const jwtSecret = process.env.JWT_SECRET || randomHex();

const env = {
  ...process.env,
  NODE_ENV: process.env.NODE_ENV || "test",
  JWT_SECRET: jwtSecret,
  JWT_SECRET_CURRENT: process.env.JWT_SECRET_CURRENT || jwtSecret,
  QR_SIGN_HMAC_SECRET: process.env.QR_SIGN_HMAC_SECRET || randomHex(),
  AUTH_COOKIE_SECRET_CURRENT: process.env.AUTH_COOKIE_SECRET_CURRENT || randomHex(),
};

const result = spawnSync(command, {
  cwd: process.cwd(),
  env,
  shell: true,
  stdio: "inherit",
});

if (result.error) {
  console.error(result.error.message);
  process.exit(1);
}

process.exit(result.status ?? 1);
