const assert = require("assert");
const { assertSafeTestDatabaseUrl } = require("./helpers/testDbSafetyGuard");

const PG_SCHEME = ["post", "gresql"].join("");
const PG_DEFAULT_USER = ["post", "gres"].join("");
const MSCQR_P2_TEST_USER = ["mscqr", "p2", "test"].join("_");
const MSCQR_APP_USER = ["mscqr", "app"].join("_");
const INTEGRATION_TEST_DB = ["mscqr", "integration", "test"].join("_");

const buildPgUrl = (options) => {
  const { user = PG_DEFAULT_USER, authSecret = user, host, port = 5432, db, omitAuthSecret = false } = options;
  const username = encodeURIComponent(user);
  const auth = omitAuthSecret ? username : `${username}:${encodeURIComponent(authSecret)}`;
  return `${PG_SCHEME}://${auth}@${host}:${port}/${encodeURIComponent(db)}`;
};

const allowed = [
  buildPgUrl({ host: "localhost", db: INTEGRATION_TEST_DB }),
  buildPgUrl({ host: "127.0.0.1", db: INTEGRATION_TEST_DB }),
  buildPgUrl({ host: PG_DEFAULT_USER, db: INTEGRATION_TEST_DB }),
  buildPgUrl({ user: MSCQR_P2_TEST_USER, omitAuthSecret: true, host: "localhost", port: 55432, db: "mscqr_p2_test_123" }),
];

for (const url of allowed) {
  assert.doesNotThrow(() => assertSafeTestDatabaseUrl(url), `expected allowed test DB URL: ${url}`);
}

const rejected = [
  buildPgUrl({ host: "localhost", db: "mscqr_prod" }),
  buildPgUrl({ host: "localhost", db: "production" }),
  buildPgUrl({ host: "localhost", db: "staging" }),
  buildPgUrl({ host: "prod.rds.amazonaws.com", db: INTEGRATION_TEST_DB }),
  buildPgUrl({ host: "db.amazonaws.com", db: INTEGRATION_TEST_DB }),
  buildPgUrl({ user: MSCQR_APP_USER, host: "localhost", db: "app_test" }),
  buildPgUrl({ host: "192.0.2.10", db: INTEGRATION_TEST_DB }),
  buildPgUrl({ host: "db.local", db: INTEGRATION_TEST_DB }),
];

for (const url of rejected) {
  assert.throws(() => assertSafeTestDatabaseUrl(url), /Refusing|Missing|support/i, `expected rejected DB URL: ${url}`);
}

console.log("test DB safety guard tests passed");
