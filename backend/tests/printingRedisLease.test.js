const assert = require("node:assert/strict");
const { randomUUID } = require("node:crypto");

const url = new URL(process.env.REDIS_URL || "");
assert(["127.0.0.1", "localhost", "redis"].includes(url.hostname), "Lease proof requires disposable Redis");
assert.equal(process.env.MSCQR_WORKER_MODE, "printing");

const { withDistributedLease } = require("../dist/services/distributedLeaseService");
const { getRedisClient, closeRedisConnections } = require("../dist/services/redisService");
const within = (promise) => Promise.race([promise, new Promise((_, reject) => {
  setTimeout(() => reject(new Error("Redis lease probe timed out")), 5_000).unref();
})]);

(async () => {
  const key = `printing-cert-${randomUUID()}`;
  let releaseFirst;
  let firstEntered;
  const firstReady = new Promise((resolve) => { firstEntered = resolve; });
  const first = withDistributedLease(key, 1000, async () => {
    firstEntered();
    await new Promise((resolve) => { releaseFirst = resolve; });
  });
  await within(Promise.race([firstReady, first.then(() => { throw new Error("First lease was not acquired"); })]));
  assert.equal((await withDistributedLease(key, 1000, async () => "overlap")).acquired, false);
  await new Promise((resolve) => setTimeout(resolve, 1200));
  let releaseSecond;
  let secondEntered;
  const secondReady = new Promise((resolve) => { secondEntered = resolve; });
  const second = withDistributedLease(key, 5000, async () => {
    secondEntered();
    await new Promise((resolve) => { releaseSecond = resolve; });
  });
  await within(Promise.race([secondReady, second.then(() => { throw new Error("Successor lease was not acquired"); })]));
  releaseFirst();
  await first;
  assert.equal((await withDistributedLease(key, 1000, async () => "stolen")).acquired, false,
    "expired owner must not release its successor's lease");
  releaseSecond();
  await second;
  assert.equal((await withDistributedLease(key, 1000, async () => "recovered")).result, "recovered");
  (await getRedisClient()).disconnect();
  await assert.rejects(withDistributedLease(key, 1000, async () => "unsafe"));
  await closeRedisConnections();
  assert.equal((await withDistributedLease(key, 1000, async () => "reconnected")).result, "reconnected");
  await closeRedisConnections();
  console.log("Redis lease overlap, expiry, owner release, disconnect and reconnect passed");
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
