const assert = require("assert");
const fs = require("fs");
const path = require("path");

const root = path.resolve(__dirname, "..");
const read = (relative) => fs.readFileSync(path.join(root, relative), "utf8");

const passkeys = read("src/services/customerWebauthnService.ts");
const repository = read("src/rls-waves/session-b/b02/publicBoundaryRepository.ts");
const ownershipHandlers = [
  "claimHandlers.ts",
  "createOwnershipTransferHandler.ts",
  "cancelOwnershipTransferHandler.ts",
  "acceptOwnershipTransferHandler.ts",
].map((file) => read(`src/controllers/verify/${file}`)).join("\n");
const claimHandler = read("src/controllers/verify/claimHandlers.ts");
const support = read("src/controllers/publicIntakeController.ts");
const feedbackHandlers = read("src/controllers/verify/feedbackHandlers.ts");
const authHandlers = read("src/controllers/verify/authHandlers.ts");
const sql = read("src/rls-waves/session-b/b02/publicVerificationFunctions.sql");
const frontend = read("../src/features/verify/components/VerifyExperience.tsx");

assert.doesNotMatch(passkeys, /prisma\.(customerWebAuthnChallenge|customerWebAuthnCredential)/);
for (const name of [
  "begin_customer_passkey",
  "load_customer_passkey",
  "finish_customer_passkey",
  "list_customer_passkeys",
  "delete_customer_passkey",
]) assert.match(repository, new RegExp(`app_public\\.${name}\\(`));

assert.match(ownershipHandlers, /customerDatabaseCapability/);
assert.match(ownershipHandlers, /CustomerOwnershipTransfer|CustomerOwnership/);
assert.doesNotMatch(ownershipHandlers, /withCanonicalDbContext|install_actor_context|prisma\.(ownership|ownershipTransfer|qRCode)/);
assert.doesNotMatch(claimHandler, /requestedCode|normalizeCode/);
assert.match(feedbackHandlers, /sessionProofHash:\s*hashToken\(sessionProof\)/);
assert.match(feedbackHandlers, /submitPublicIncident[\s\S]+?sessionId,[\s\S]+?sessionProofHash/);
assert.match(authHandlers, /readCustomerVerifyDatabaseSession\(req\.customerDatabaseCapability\)/);
assert.doesNotMatch(authHandlers, /revokeCustomerVerifyDatabaseSession\([^)]*\)\.catch/);
assert(frontend.includes('codeParam ? `/verify/${encodeURIComponent(codeParam)}` : "/verify"'));
assert.doesNotMatch(frontend, /params\.set\("t",\s*token\)/);

assert.match(support, /verifiedCode:\s*data\.verificationCode/);
assert.doesNotMatch(support, /qrCodeId:\s*data|licenseeId:\s*data|organizationId:\s*data/);
assert.match(sql, /encode\(sha256\(convert_to\(p_capability,'UTF8'\)\),'hex'\)/);
assert.match(sql, /UPDATE public\."CustomerWebAuthnChallenge"\s+SET "consumedAt"=p_checked_at[\s\S]+?"consumedAt" IS NULL/);
assert.doesNotMatch(sql, /GRANT EXECUTE ON ALL FUNCTIONS|GRANT ALL ON ALL FUNCTIONS/);

console.log("public verification customer ownership/passkey boundary contract passed");
