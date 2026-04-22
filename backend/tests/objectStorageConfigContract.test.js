const assert = require("assert");
const path = require("path");

const modulePath = path.resolve(__dirname, "../dist/services/objectStorageService.js");

const restoreKeys = [
  "OBJECT_STORAGE_BUCKET",
  "OBJECT_STORAGE_REGION",
  "AWS_REGION",
  "OBJECT_STORAGE_ENDPOINT",
  "OBJECT_STORAGE_ACCESS_KEY",
  "OBJECT_STORAGE_SECRET_KEY",
];

const originalEnv = Object.fromEntries(restoreKeys.map((key) => [key, process.env[key]]));

const freshConfiguration = () => {
  delete require.cache[modulePath];
  return require(modulePath).getObjectStorageConfiguration();
};

for (const key of restoreKeys) {
  delete process.env[key];
}

process.env.OBJECT_STORAGE_BUCKET = "mscqr-artifacts";
process.env.OBJECT_STORAGE_REGION = "eu-west-2";
process.env.OBJECT_STORAGE_ENDPOINT = "http://minio.local:9000";

let configuration = freshConfiguration();
assert.strictEqual(configuration.configured, false, "custom endpoints must fail closed without explicit app credentials");
assert.strictEqual(configuration.mode, "invalid");
assert.match(String(configuration.reason || ""), /OBJECT_STORAGE_ACCESS_KEY and OBJECT_STORAGE_SECRET_KEY/i);

process.env.OBJECT_STORAGE_ACCESS_KEY = "placeholder-access-key";
process.env.OBJECT_STORAGE_SECRET_KEY = "placeholder-secret-key";

configuration = freshConfiguration();
assert.strictEqual(configuration.configured, true, "explicit object storage credentials should satisfy the runtime contract");
assert.strictEqual(configuration.mode, "static-credentials");

for (const [key, value] of Object.entries(originalEnv)) {
  if (value === undefined) delete process.env[key];
  else process.env[key] = value;
}

console.log("object storage config contract tests passed");
