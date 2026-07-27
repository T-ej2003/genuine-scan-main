#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { scanSharedTableAccesses, scannerScope } from "./lib/shared-table-rls-compatibility-scanner.mjs";

const repoRoot = path.resolve(new URL("..", import.meta.url).pathname);
const outputPath = path.join(repoRoot, "documents/security/mscqr_shared_table_rls_compatibility_matrix_2026-07-15.json");

const isTest = (row) => row.sourceFile.includes("/tests/");
const isCli = (row) => row.sourceFile.startsWith("backend/scripts/") || row.sourceFile === "backend/prisma/seed.ts";
const isBackground = (row) => /(?:notification|incidentEmail|compliancePack|printValidationEvidence|dashboardSnapshot)/i.test(row.sourceFile);
const isStartup = (row) => /(?:superAdminBootstrap|seed)/i.test(`${row.sourceFile}:${row.serviceFunction}`);
const isPreAuth = (row) => /authBootstrapRepository|passwordResetService/.test(row.sourceFile)
  || (/emailVerificationService/.test(row.sourceFile) && row.serviceFunction === "confirmEmailVerification")
  || (/inviteService/.test(row.sourceFile) && ["acceptInvite", "getInvitePreview"].includes(row.serviceFunction))
  || ["loginWithPassword", "refreshSession"].includes(row.serviceFunction);
const isSelfService = (row) => /(?:accountController|authController|authAdminSecurityController|authSessionController|middleware\/auth)/.test(row.sourceFile)
  || /(?:My|Self|issueSession|hydrateTenant|requestEmailChangeVerification|resolveInviteActorContext)/i.test(row.serviceFunction);
const isPlatformAdmin = (row) => /(?:licenseeController|repair-admin|create-super-admin|resetSuperAdmin|break-glass|superAdminBootstrap|getOrCreatePlatformOrgId)/i.test(`${row.sourceFile}:${row.serviceFunction}`);
const isLicenseeAdmin = (row) => /(?:userController|userService|licenseeInviteController)/i.test(row.sourceFile)
  || (/inviteService/.test(row.sourceFile) && ["createInvite", "inferOrgIdForLicensee"].includes(row.serviceFunction));

const executionSurface = (row) => isCli(row) ? "cli"
  : isStartup(row) ? "startup"
    : isBackground(row) ? "background-job"
      : row.sourceFile.includes("/controllers/") || row.sourceFile.includes("/middleware/") ? "http"
        : isTest(row) ? "internal" : "internal";
const authenticationStage = (row) => isCli(row) || isBackground(row) || isStartup(row) || isTest(row) ? "system"
  : isPreAuth(row) ? "pre-auth"
    : /middleware\/auth/.test(row.sourceFile) ? "password-verified"
      : "fully-authenticated";
const scope = (row) => isPreAuth(row) ? "pre-auth"
  : isSelfService(row) ? "self"
    : row.table === "ManufacturerLicenseeLink" ? "manufacturer-link"
      : isPlatformAdmin(row) ? "platform-wide"
        : isLicenseeAdmin(row) ? "same-licensee"
          : row.table === "Organization" ? "same-organization"
            : "unknown";
const requiredRole = (row, stage, rowScope) => stage === "pre-auth" ? "mscqr_staging_app through a named narrow function"
  : stage === "system" ? "not yet designed"
    : rowScope === "platform-wide" ? "platform administrator with recent MFA for mutations"
      : rowScope === "same-licensee" ? "licensee administrator within actor tenant"
        : rowScope === "self" ? "authenticated actor matching User.id and User.role"
          : rowScope === "manufacturer-link" ? "manufacturer or licensee administrator within the selected link"
            : "explicit tenant role not yet proven";
const outcome = (row, rowScope, context) => {
  if (row.operation === "INSERT" || row.operation === "DELETE" || row.operation === "UPSERT") return "denied";
  if (row.operation === "UPDATE") {
    return row.table === "User" && context === "transaction-local"
      && (rowScope === "self" || row.serviceFunction === "loginWithPassword") ? "allowed" : "denied";
  }
  if (context === "transaction-local" && row.table === "User" && rowScope === "self") return "allowed";
  return context === "transaction-local" && rowScope !== "unknown" && !isTest(row) ? "partially-allowed" : "denied";
};
const remediation = (row, stage, rowScope, context) => {
  if (row.serviceFunction === "loginWithPassword" && row.table === "User" && row.operation === "UPDATE" && context === "transaction-local") return "none";
  if (stage === "pre-auth" && !(row.serviceFunction === "loginWithPassword" && context === "transaction-local")) return "security-definer-boundary";
  if (stage === "system") return "system-role-design";
  if (["INSERT", "DELETE", "UPSERT"].includes(row.operation)) return "new-policy";
  if (row.operation === "UPDATE" && !(row.table === "User" && rowScope === "self")) return "new-policy";
  if (context === "none") return row.client === "prisma" ? "repository-wrapper" : "transaction-context";
  return "none";
};

const rows = scanSharedTableAccesses(repoRoot).map((row) => {
  const surface = executionSurface(row);
  const stage = authenticationStage(row);
  const rowScope = scope(row);
  const context = row.syntacticRlsContext;
  const policyOutcome = outcome(row, rowScope, context);
  const required = remediation(row, stage, rowScope, context);
  return {
    id: row.id,
    table: row.table,
    sourceFile: row.sourceFile,
    line: row.line,
    entryPoint: `${surface}:${row.serviceFunction}`,
    serviceFunction: row.serviceFunction,
    executionSurface: surface,
    operation: row.operation,
    scope: rowScope,
    requiredRole: requiredRole(row, stage, rowScope),
    authenticationStage: stage,
    currentRlsContext: context,
    contextFieldsRequired: stage === "system" ? [] : row.serviceFunction === "loginWithPassword" && context === "transaction-local"
      ? ["app.user_id", "app.role", "app.licensee_id", "app.organization_id", "app.manufacturer_id", "app.is_platform_admin"]
      : rowScope === "self" ? ["app.user_id", "app.role"]
      : rowScope === "same-licensee" ? ["app.user_id", "app.role", "app.licensee_id", "app.organization_id"]
        : rowScope === "platform-wide" ? ["app.user_id", "app.role", "app.is_platform_admin"]
          : rowScope === "manufacturer-link" ? ["app.user_id", "app.role", "app.manufacturer_id", "app.licensee_id"]
            : [],
    currentPolicyOutcome: policyOutcome,
    compatibilityRisk: required === "none" && policyOutcome === "allowed" ? "low"
      : ["INSERT", "DELETE", "UPSERT", "UPDATE"].includes(row.operation) || stage === "pre-auth" || stage === "system" ? "blocking" : "high",
    requiredRemediation: required,
    evidence: [
      `${row.sourceFile}:${row.line}: ${row.evidenceText}`,
      `Scanner observed client=${row.client}, method=${row.method}, syntacticRlsContext=${context}.`,
      policyOutcome === "allowed"
        ? "Reviewed actor-self User predicate and transaction-local actor context match this operation."
        : "No exact policy-plus-runtime-context proof permits this operation under the reviewed shared-table posture.",
    ],
  };
});

const functionRows = [
  {
    id: "shared-auth-lookup-password-user", table: "User",
    sourceFile: "backend/src/services/auth/authBootstrapRepository.ts", line: 64,
    entryPoint: "http:loginWithPassword", serviceFunction: "lookupPasswordBootstrapUser",
    executionSurface: "http", operation: "RAW_SQL", scope: "pre-auth",
    requiredRole: "mscqr_staging_app through app_auth.lookup_password_user(text)", authenticationStage: "pre-auth",
    currentRlsContext: "none", contextFieldsRequired: [], currentPolicyOutcome: "allowed", compatibilityRisk: "low",
    requiredRemediation: "none",
    evidence: ["Exact reviewed SECURITY DEFINER function app_auth.lookup_password_user(text).", "Fixed search_path=pg_catalog; PUBLIC and read-role EXECUTE revoked; app-role EXECUTE granted."],
  },
  {
    id: "shared-auth-record-password-failure", table: "User",
    sourceFile: "backend/src/services/auth/authBootstrapRepository.ts", line: 86,
    entryPoint: "http:loginWithPassword", serviceFunction: "recordPasswordLoginFailure",
    executionSurface: "http", operation: "RAW_SQL", scope: "pre-auth",
    requiredRole: "mscqr_staging_app through app_auth.record_password_failure(text,timestamp,integer,integer)", authenticationStage: "password-verified",
    currentRlsContext: "none", contextFieldsRequired: [], currentPolicyOutcome: "allowed", compatibilityRisk: "low",
    requiredRemediation: "none",
    evidence: ["Exact reviewed SECURITY DEFINER function app_auth.record_password_failure(text,timestamp without time zone,integer,integer).", "Function owner receives only reviewed User column privileges."],
  },
];

const document = {
  schemaVersion: 1,
  generatedFor: "2026-07-15 shared-table FORCE RLS compatibility review",
  scannerScope,
  policyBasis: "documents/security/mscqr_staging_rls_shared_batch_phase_apply_2026-07-15.sql (apply remains blocked)",
  conservativeClassification: "allowed requires exact policy and transaction/function-boundary evidence; unknown or contextless access is denied/high-or-blocking",
  operations: [...rows, ...functionRows].sort((a, b) => a.sourceFile.localeCompare(b.sourceFile) || a.line - b.line || a.id.localeCompare(b.id)),
};

fs.writeFileSync(outputPath, `${JSON.stringify(document, null, 2)}\n`, { encoding: "utf8" });
console.log(JSON.stringify({ output: path.relative(repoRoot, outputPath), operations: document.operations.length }));
