const assert = require("node:assert/strict");
const { readFileSync } = require("node:fs");
const path = require("node:path");

const repository = readFileSync(path.join(__dirname,
  "../src/rls-waves/session-b/b02/publicBoundaryRepository.ts"), "utf8");
const sql = readFileSync(path.join(__dirname,
  "../src/rls-waves/session-b/b02/publicVerificationFunctions.sql"), "utf8");

assert.match(repository, /randomBytes\(32\)\.toString\("base64url"\)/);
assert.match(repository, /sessionStart\.hash/);
assert.match(repository, /REPORT_SESSION_RESULTS = new Set\(\["AUTHENTIC", "AUTHENTIC_REPEAT", "REVIEW", "BLOCKED", "NOT_READY"\]\)/);
assert.match(repository, /sessionStartToken:\s*row\.ownershipClaimAvailable \|\| reportSessionAvailable \? rawToken : null/);
assert.doesNotMatch(sql, /p_session_start_token(?!_hash)/);
assert.match(sql, /publicSessionStart'.*'tokenHash'/s);
assert.match(sql, /consumedAt/);
assert.match(sql, /interval '15 minutes'/);
assert.match(sql, /presentationSnapshot,ownershipClaimAvailable/);
assert(
  sql.indexOf("set_config('app.public_verification_decision_id',session_row.\"verificationDecisionId\",true)")
    < sql.indexOf("presentationSnapshot,ownershipClaimAvailable")
);

console.log("public verification session-start bearer contract passed");
