const assert = require("assert");

const { getOrComputeVersionedCache } = require("../dist/services/versionedCacheService");
const { closeRedisConnections } = require("../dist/services/redisService");

(async () => {
  let calls = 0;
  const [first, second, third] = await Promise.all([
    getOrComputeVersionedCache("test-coalesce", "tenant:user:query", 5, async () => {
      calls += 1;
      await new Promise((resolve) => setTimeout(resolve, 10));
      return { value: 1 };
    }),
    getOrComputeVersionedCache("test-coalesce", "tenant:user:query", 5, async () => {
      calls += 1;
      return { value: 2 };
    }),
    getOrComputeVersionedCache("test-coalesce", "tenant:user:query", 5, async () => {
      calls += 1;
      return { value: 3 };
    }),
  ]);

  assert.deepStrictEqual(first, { value: 1 });
  assert.deepStrictEqual(second, { value: 1 });
  assert.deepStrictEqual(third, { value: 1 });
  assert.strictEqual(calls, 1, "same cache key should coalesce concurrent computation");

  const cached = await getOrComputeVersionedCache("test-coalesce", "tenant:user:query", 5, async () => {
    calls += 1;
    return { value: 4 };
  });
  assert.deepStrictEqual(cached, { value: 1 });
  assert.strictEqual(calls, 1, "cache hit should avoid recompute");

  console.log("readCacheCoalescing.test passed");
})().finally(closeRedisConnections).catch((error) => {
  console.error(error);
  process.exit(1);
});
