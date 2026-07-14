#!/usr/bin/env node
import { parseRuntimeIdentityProof } from "../lib/staging-database-role-credentials-core.mjs";
import { runtimeIdentityParserFixtures } from "../fixtures/staging-ecs-runtime-identity-parser-fixtures.mjs";

const results = runtimeIdentityParserFixtures.map(({ name, result, expected, expectedIdentity }) => {
  let actual = "ok";
  try { parseRuntimeIdentityProof(result, expectedIdentity); }
  catch (error) { actual = error.code; }
  if (actual !== expected) throw new Error(`Parser fixture ${name} returned an unexpected sanitized classification.`);
  return { name, classification: actual };
});

console.log(JSON.stringify({ status: "passed", mutatesAws: false, fixtureCount: results.length, results }, null, 2));
