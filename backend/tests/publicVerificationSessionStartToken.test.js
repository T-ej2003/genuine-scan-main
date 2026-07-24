const assert = require("node:assert/strict");
const { readFileSync } = require("node:fs");
const path = require("node:path");

const repository = readFileSync(path.join(__dirname,
  "../src/rls-waves/session-b/b02/publicBoundaryRepository.ts"), "utf8");
const sql = readFileSync(path.join(__dirname,
  "../src/rls-waves/session-b/b02/publicVerificationFunctions.sql"), "utf8");

assert.match(repository, /randomBytes\(32\)\.toString\("base64url"\)/);
assert.match(repository, /sessionStart\.hash/);
assert.match(repository, /sessionStartToken:\s*row\.ownershipClaimAvailable\s*\?\s*sessionStart\.raw\s*:\s*null/);
assert.doesNotMatch(sql, /p_session_start_token(?!_hash)/);
assert.match(sql, /publicSessionStart'.*'tokenHash'/s);
assert.match(sql, /consumedAt/);
assert.match(sql, /interval '15 minutes'/);

console.log("public verification session-start bearer contract passed");
