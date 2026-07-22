import assert from "node:assert/strict";

// A function contract is deliberately separate from a workflow delegation. It
// records the database authority that a repository call contributes to its
// canonical workflow. A disposable fixture can prove a function's local
// behavior, but cannot establish production table authority by itself.
const refreshFixture = "backend/tests/rls-wave-b/b01/refreshSessionPostgres18.fixture.sql";

export const NAMED_SQL_FUNCTION_DEFINITION_EVIDENCE = Object.freeze([
  {
    schema: "app_auth",
    name: "claim_refresh_token_rotation",
    signature: "text[],timestamp without time zone,text",
    definitionLocation: refreshFixture,
    definitionStatus: "fixture-only-non-production",
  },
  {
    schema: "app_auth",
    name: "load_refresh_session_state",
    signature: "text,text[],text,text,timestamp without time zone,text",
    definitionLocation: refreshFixture,
    definitionStatus: "fixture-only-non-production",
  },
  {
    schema: "app_auth",
    name: "create_refresh_mfa_challenge",
    signature: "text,text[],text,text,text,integer,text,text[],text,text,integer,timestamp without time zone,timestamp without time zone,text",
    definitionLocation: refreshFixture,
    definitionStatus: "fixture-only-non-production",
  },
  {
    schema: "app_auth",
    name: "revoke_refresh_token_scope",
    signature: "text,text[],text,text,text,timestamp without time zone,text",
    definitionLocation: refreshFixture,
    definitionStatus: "fixture-only-non-production",
  },
  {
    schema: "app_auth",
    name: "complete_refresh_token_rotation",
    signature: "text,text[],text,text,text,timestamp without time zone,text,text,timestamp without time zone,timestamp without time zone,timestamp without time zone,text",
    definitionLocation: refreshFixture,
    definitionStatus: "fixture-only-non-production",
  },
]);

const b01Source = "backend/src/rls-waves/session-b/b01/b01RefreshRotationFunctions.sql";
const b01Rollback = "backend/src/rls-waves/session-b/b01/b01RefreshRotationRollback.sql";
const authenticatedSessionSource = "backend/src/rls-waves/session-b/b01/authenticatedSessionCapabilityFunctions.sql";
const authenticatedSessionRollback = "backend/src/rls-waves/session-b/b01/authenticatedSessionCapabilityRollback.sql";
const b01Workflow = "workflow-internal-backend-src-services-auth-auth-service-ts-refresh-session";
const b01Context = "SECURITY DEFINER sets transaction-local B01 bearer-hash scope before the first RefreshToken read, then derives every user, tenant, manufacturer and MFA scope from the locked predecessor row. Caller app.* settings are never read as authority.";
const b01Security = Object.freeze({
  mode: "SECURITY DEFINER",
  ownerIdentity: "identity-auth-function-owner",
  ownerRole: "authOwner",
  searchPath: "pg_catalog,public",
  publicExecute: "revoked",
  runtimeExecuteGrantees: ["preauth"],
  functionSource: b01Source,
  rollbackDefinition: b01Rollback,
  deploymentPhase: "session-b-b01",
});
const b01Tables = Object.freeze({
  claim: [
    ["RefreshToken", "SELECT"], ["RefreshToken", "UPDATE"], ["User", "SELECT"],
    ["ManufacturerLicenseeLink", "SELECT"], ["Licensee", "SELECT"], ["Organization", "SELECT"],
    ["AuditLogOutbox", "INSERT"],
  ],
  state: [
    ["RefreshToken", "SELECT"], ["User", "SELECT"], ["ManufacturerLicenseeLink", "SELECT"],
    ["Licensee", "SELECT"], ["Organization", "SELECT"], ["AdminMfaCredential", "SELECT"],
    ["AdminWebAuthnCredential", "SELECT"], ["UserMfaFactor", "SELECT"], ["UserBackupCode", "SELECT"],
    ["AuditLogOutbox", "INSERT"],
  ],
  challenge: [["RefreshToken", "SELECT"], ["User", "SELECT"], ["AuthMfaChallenge", "INSERT"], ["AuditLogOutbox", "INSERT"]],
  revoke: [["RefreshToken", "SELECT"], ["RefreshToken", "UPDATE"], ["User", "SELECT"], ["AuditLogOutbox", "INSERT"]],
  complete: [["RefreshToken", "SELECT"], ["RefreshToken", "INSERT"], ["RefreshToken", "UPDATE"], ["User", "SELECT"], ["ManufacturerLicenseeLink", "SELECT"], ["Licensee", "SELECT"], ["Organization", "SELECT"], ["AuditLogOutbox", "INSERT"]],
});

// A function is production-reviewed only when its deployable definition,
// contract, rollback and exact table-command evidence live together here.
export const NAMED_SQL_FUNCTION_CONTRACTS = Object.freeze([
  {
    id: "b01-issue-authenticated-session", schema: "app_auth", name: "issue_authenticated_session_capability",
    signature: "text,text,text,text,timestamp without time zone", returnType: "TABLE(id text, expiresAt timestamp without time zone)",
    identityArguments: "p_refresh_token_id text, p_refresh_token_hash text, p_capability text, p_assurance text, p_expires_at timestamp without time zone",
    definitionLocation: authenticatedSessionSource, definitionKind: "checked-in-production-package", definitionStatus: "production-reviewed",
    security: { ...b01Security, functionSource: authenticatedSessionSource, rollbackDefinition: authenticatedSessionRollback },
    tableCommands: [["RefreshToken", "SELECT"], ["RefreshToken", "UPDATE"]],
    context: "Issues a capability only for the locked active refresh-session row after the caller presents its exact bearer-derived refresh hash; user and assurance are derived from that row.",
    canonicalWorkflowIds: [], repositoryCallers: ["backend/src/services/auth/authenticatedSessionCapabilityService.ts:createAuthenticatedSessionCapability"], inputAuthority: "refresh session identifier plus exact bearer-derived hash select a candidate; the raw capability is hashed in PostgreSQL", outputColumns: ["id", "expiresAt"], disposableProbes: ["authenticated-session-capability-postgres18"],
  },
  {
    id: "b01-require-authenticated-session", schema: "app_auth", name: "require_authenticated_session",
    signature: "text,text,text", returnType: "TABLE(sessionId text, userId text, role text, organizationId text, licenseeId text, assurance text)",
    identityArguments: "p_capability text, p_purpose text, p_request_id text",
    definitionLocation: authenticatedSessionSource, definitionKind: "checked-in-production-package", definitionStatus: "production-reviewed",
    security: { ...b01Security, functionSource: authenticatedSessionSource, rollbackDefinition: authenticatedSessionRollback, runtimeExecuteGrantees: ["app"] },
    tableCommands: [["RefreshToken", "SELECT"], ["RefreshToken", "UPDATE"], ["User", "SELECT"]],
    context: "Hashes the opaque capability in PostgreSQL, derives live user authority from the linked active session, and overwrites transaction-local authenticated context before protected access.",
    canonicalWorkflowIds: [], repositoryCallers: [], inputAuthority: "opaque 256-bit bearer capability; purpose and request ID are attribution only", outputColumns: ["sessionId", "userId", "role", "organizationId", "licenseeId", "assurance"], disposableProbes: ["authenticated-session-capability-postgres18"],
  },
  {
    id: "b01-revoke-authenticated-session", schema: "app_auth", name: "revoke_authenticated_session_capability",
    signature: "text,text,text,text", returnType: "TABLE(revoked boolean)",
    identityArguments: "p_capability text, p_target_refresh_token_id text, p_reason text, p_request_id text",
    definitionLocation: authenticatedSessionSource, definitionKind: "checked-in-production-package", definitionStatus: "production-reviewed",
    security: { ...b01Security, functionSource: authenticatedSessionSource, rollbackDefinition: authenticatedSessionRollback, runtimeExecuteGrantees: ["app"] },
    tableCommands: [["RefreshToken", "SELECT"], ["RefreshToken", "UPDATE"], ["User", "SELECT"]],
    context: "Verifies the opaque capability before deriving its user and revoking only a capability row bound to that verified user.",
    canonicalWorkflowIds: [], repositoryCallers: ["backend/src/services/auth/authenticatedSessionCapabilityService.ts:revokeAuthenticatedSessionByRefreshToken"], inputAuthority: "target session ID is a candidate only; the verified capability derives the authoritative user", outputColumns: ["revoked"], disposableProbes: ["authenticated-session-capability-postgres18"],
  },
  {
    id: "b01-revoke-all-authenticated-sessions", schema: "app_auth", name: "revoke_all_authenticated_session_capabilities",
    signature: "text,text,text", returnType: "TABLE(revokedCount integer)",
    identityArguments: "p_capability text, p_reason text, p_request_id text",
    definitionLocation: authenticatedSessionSource, definitionKind: "checked-in-production-package", definitionStatus: "production-reviewed",
    security: { ...b01Security, functionSource: authenticatedSessionSource, rollbackDefinition: authenticatedSessionRollback, runtimeExecuteGrantees: ["app"] },
    tableCommands: [["RefreshToken", "SELECT"], ["RefreshToken", "UPDATE"], ["User", "SELECT"]],
    context: "Verifies the opaque capability before deriving the only user whose active capabilities may be revoked.",
    canonicalWorkflowIds: [], repositoryCallers: ["backend/src/services/auth/authenticatedSessionCapabilityService.ts:revokeAuthenticatedSessionsForUser"], inputAuthority: "the caller supplies no user authority; the verified capability derives the target user", outputColumns: ["revokedCount"], disposableProbes: ["authenticated-session-capability-postgres18"],
  },
  {
    id: "b01-claim-refresh-token-rotation", schema: "app_auth", name: "claim_refresh_token_rotation",
    signature: "text[],timestamp without time zone,text", returnType: "TABLE(disposition text, tokenId text, userId text, role text, organizationId text, licenseeId text, manufacturerId text, authAssurance text, expiresAt timestamp without time zone, authenticatedAt timestamp without time zone, mfaVerifiedAt timestamp without time zone)",
    identityArguments: "p_hashes text[], p_checked_at timestamp without time zone, p_request_id text",
    definitionLocation: b01Source, definitionKind: "checked-in-production-package", definitionStatus: "production-reviewed",
    security: b01Security, tableCommands: b01Tables.claim, context: b01Context, canonicalWorkflowIds: [b01Workflow],
    repositoryCallers: ["backend/src/rls-waves/session-b/b01/sessionCredentialRepository.ts:claimRefreshTokenRotation"],
    inputAuthority: "1..3 validated bearer-token hashes and request metadata only", outputColumns: ["disposition", "tokenId", "userId", "role", "organizationId", "licenseeId", "manufacturerId", "authAssurance", "expiresAt", "authenticatedAt", "mfaVerifiedAt"], disposableProbes: ["b01-refresh-rotation-real-schema"],
  },
  {
    id: "b01-load-refresh-session-state", schema: "app_auth", name: "load_refresh_session_state",
    signature: "text,text[],text,text,timestamp without time zone,text", returnType: "TABLE(userId text, email text, name text, role text, legacyLicenseeId text, legacyOrganizationId text, emailVerifiedAt timestamp without time zone, sessionLicenseeId text, sessionOrganizationId text, scopeVersion text, selectedLicenseeId text, selectedLicenseeName text, selectedLicenseePrefix text, selectedLicenseeBrandName text, selectedLicenseeOrganizationId text, linkedLicensees jsonb, mfaRequired boolean, mfaEnabled boolean, mfaEnrolled boolean, mfaLastUsedAt timestamp without time zone, mfaMethods text[], mfaPreferredMethod text)",
    identityArguments: "p_token_id text, p_hashes text[], p_requested_licensee_id text, p_requested_scope_version text, p_checked_at timestamp without time zone, p_request_id text",
    definitionLocation: b01Source, definitionKind: "checked-in-production-package", definitionStatus: "production-reviewed",
    security: b01Security, tableCommands: b01Tables.state, context: b01Context, canonicalWorkflowIds: [b01Workflow],
    repositoryCallers: ["backend/src/rls-waves/session-b/b01/sessionCredentialRepository.ts:loadRefreshSessionState"],
    inputAuthority: "claimed predecessor identity plus the original bearer hashes; requested manufacturer scope is selection-only", outputColumns: ["userId", "email", "name", "role", "legacyLicenseeId", "legacyOrganizationId", "emailVerifiedAt", "sessionLicenseeId", "sessionOrganizationId", "scopeVersion", "selectedLicenseeId", "selectedLicenseeName", "selectedLicenseePrefix", "selectedLicenseeBrandName", "selectedLicenseeOrganizationId", "linkedLicensees", "mfaRequired", "mfaEnabled", "mfaEnrolled", "mfaLastUsedAt", "mfaMethods", "mfaPreferredMethod"], disposableProbes: ["b01-refresh-rotation-real-schema"],
  },
  {
    id: "b01-create-refresh-mfa-challenge", schema: "app_auth", name: "create_refresh_mfa_challenge",
    signature: "text,text[],text,text,text,integer,text,text[],text,text,integer,timestamp without time zone,timestamp without time zone,text", returnType: "TABLE(challengeId text, created boolean)",
    identityArguments: "p_token_id text, p_hashes text[], p_user_id text, p_ticket_hash text, p_session_binding_hash text, p_risk_score integer, p_risk_level text, p_reasons text[], p_ip_hash text, p_user_agent_hash text, p_max_attempts integer, p_expires_at timestamp without time zone, p_created_at timestamp without time zone, p_request_id text",
    definitionLocation: b01Source, definitionKind: "checked-in-production-package", definitionStatus: "production-reviewed",
    security: b01Security, tableCommands: b01Tables.challenge, context: b01Context, canonicalWorkflowIds: [b01Workflow],
    repositoryCallers: ["backend/src/rls-waves/session-b/b01/sessionCredentialRepository.ts:createRefreshMfaChallengeRecord"],
    inputAuthority: "claimed predecessor identity; challenge payload is validated but cannot select an actor", outputColumns: ["challengeId", "created"], disposableProbes: ["b01-refresh-rotation-real-schema"],
  },
  {
    id: "b01-revoke-refresh-token-scope", schema: "app_auth", name: "revoke_refresh_token_scope",
    signature: "text,text[],text,text,text,timestamp without time zone,text", returnType: "TABLE(revokedCount integer)",
    identityArguments: "p_token_id text, p_hashes text[], p_user_id text, p_scope text, p_reason text, p_revoked_at timestamp without time zone, p_request_id text",
    definitionLocation: b01Source, definitionKind: "checked-in-production-package", definitionStatus: "production-reviewed",
    security: b01Security, tableCommands: b01Tables.revoke, context: b01Context, canonicalWorkflowIds: [b01Workflow],
    repositoryCallers: ["backend/src/rls-waves/session-b/b01/sessionCredentialRepository.ts:revokeRefreshTokenRotationScope"],
    inputAuthority: "claimed predecessor identity; scope is a fixed enum and target user is rebound to the predecessor", outputColumns: ["revokedCount"], disposableProbes: ["b01-refresh-rotation-real-schema"],
  },
  {
    id: "b01-complete-refresh-token-rotation", schema: "app_auth", name: "complete_refresh_token_rotation",
    signature: "text,text[],text,text,text,timestamp without time zone,text,text,timestamp without time zone,timestamp without time zone,timestamp without time zone,text", returnType: "TABLE(id text, expiresAt timestamp without time zone)",
    identityArguments: "p_token_id text, p_hashes text[], p_user_id text, p_organization_id text, p_token_hash text, p_expires_at timestamp without time zone, p_ip_hash text, p_user_agent text, p_authenticated_at timestamp without time zone, p_mfa_verified_at timestamp without time zone, p_rotated_at timestamp without time zone, p_request_id text",
    definitionLocation: b01Source, definitionKind: "checked-in-production-package", definitionStatus: "production-reviewed",
    security: b01Security, tableCommands: b01Tables.complete, context: b01Context, canonicalWorkflowIds: [b01Workflow],
    repositoryCallers: ["backend/src/rls-waves/session-b/b01/sessionCredentialRepository.ts:completeRefreshTokenRotation"],
    inputAuthority: "claimed predecessor identity; successor hash is supplied by the application and raw successor is never accepted or retained", outputColumns: ["id", "expiresAt"], disposableProbes: ["b01-refresh-rotation-real-schema"],
  },
]);

export const namedFunctionKey = ({ schema, name }) => `${schema}.${name}`;

export const validateNamedSqlFunctionContracts = (contracts = NAMED_SQL_FUNCTION_CONTRACTS) => {
  const ids = new Set();
  const keys = new Set();
  for (const contract of contracts) {
    assert.match(contract.id || "", /^[a-z0-9-]+$/, "named SQL function contract has an invalid ID");
    assert.match(contract.schema || "", /^[a-z_][a-z0-9_]*$/, "named SQL function contract has an invalid schema");
    assert.match(contract.name || "", /^[a-z_][a-z0-9_]*$/, "named SQL function contract has an invalid name");
    assert(contract.signature != null, "named SQL function contract has a missing signature");
    assert.match(contract.definitionLocation || "", /\.(?:sql|psql)$/, "named SQL function contract has no checked-in SQL definition location");
    assert(contract.definitionKind === "checked-in-disposable-certification-fixture" || contract.definitionKind === "checked-in-production-package", "named SQL function contract has an invalid definition kind");
    assert(contract.tableCommands?.length, "named SQL function contract has no reviewed table-command evidence");
    assert(contract.context?.trim(), "named SQL function contract has no context contract");
    assert(contract.returnType?.trim(), "named SQL function contract has no return type");
    assert(contract.identityArguments?.trim(), "named SQL function contract has no identity arguments");
    assert(contract.definitionStatus === "production-reviewed", "named SQL function contract has an unreviewed definition");
    assert(contract.security?.mode === "SECURITY DEFINER", "named SQL function contract has an unsafe security mode");
    assert(contract.security?.ownerIdentity && contract.security?.ownerRole, "named SQL function contract has no controlled owner");
    assert(contract.security?.searchPath === "pg_catalog,public", "named SQL function contract has an unsafe search path");
    assert(contract.security?.publicExecute === "revoked", "named SQL function contract leaves PUBLIC execution unresolved");
    assert(contract.security?.runtimeExecuteGrantees?.length, "named SQL function contract has no runtime execute grantee");
    assert(contract.security?.rollbackDefinition?.endsWith(".sql"), "named SQL function contract has no rollback SQL");
    assert(contract.disposableProbes?.length, "named SQL function contract has no disposable probe");
    for (const [table, command] of contract.tableCommands) {
      assert.match(table || "", /^[A-Za-z][A-Za-z0-9_]*$/, "named SQL function contract has malformed table evidence");
      assert(["SELECT", "INSERT", "UPDATE", "DELETE"].includes(command), "named SQL function contract has malformed command evidence");
    }
    assert(!ids.has(contract.id), `duplicate named SQL function contract ID: ${contract.id}`);
    assert(!keys.has(namedFunctionKey(contract)), `duplicate named SQL function contract: ${namedFunctionKey(contract)}`);
    ids.add(contract.id);
    keys.add(namedFunctionKey(contract));
  }
  return [...contracts].sort((a, b) => namedFunctionKey(a).localeCompare(namedFunctionKey(b)));
};

export const namedFunctionContractFor = (functionName, contracts = NAMED_SQL_FUNCTION_CONTRACTS) =>
  contracts.find((contract) => namedFunctionKey(contract) === functionName) || null;

export const namedFunctionDefinitionEvidenceFor = (functionName, evidence = NAMED_SQL_FUNCTION_DEFINITION_EVIDENCE) =>
  evidence.find((item) => namedFunctionKey(item) === functionName) || null;
