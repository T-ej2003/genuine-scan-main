import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { applicationPathCertificationFamilies } from "./application-path-certifications.mjs";

export const cleanRoomRepoRoot = path.resolve(fileURLToPath(new URL("../../..", import.meta.url)));
export const cleanRoomSourcePaths = [...new Set([
  "documents/security/rls-program/tables.json",
  "documents/security/rls-program/workflows.json",
  "documents/security/rls-program/command-semantics.json",
  "documents/security/rls-program/runtime-identities.json",
  "documents/security/rls-program/object-ownership-chain.json",
  "documents/security/rls-program/essential-workflow-allowlist.json",
  "documents/security/rls-program/context-boundary-families.json",
  "documents/security/rls-program/workflow-three-session-partition.json",
  "backend/prisma/schema.prisma",
  "scripts/rls/generate-full-rls-sql.mjs",
  "scripts/rls/generate-clean-room-rls-sql.mjs",
  "scripts/rls/verify-full-rls-package.mjs",
  "scripts/rls/certify-clean-room-database.mjs",
  "scripts/rls/create-production-rls-approval.mjs",
  "scripts/rls/lib/clean-room-source-contract.mjs",
  "scripts/rls/lib/program-inventory.mjs",
  "scripts/rls/lib/table-inventory-baseline.mjs",
  "scripts/rls/lib/application-path-certifications.mjs",
  "scripts/rls/lib/named-sql-function-contracts.mjs",
  "scripts/rls/lib/restricted-owner-projection-contract.mjs",
  "backend/Dockerfile",
  "backend/scripts/full-rls-green-executor-core.mjs",
  "backend/scripts/staging-full-rls-green-executor.mjs",
  "backend/scripts/production-full-rls-green-executor.mjs",
  "backend/scripts/production-green-canary-provision.mjs",
  "backend/scripts/production-green-application-canary.mjs",
  "backend/scripts/production-rls-approval.mjs",
  "backend/tests/qrSystemPostgres18.test.js",
  "documents/security/rls-program/staging-full-rls-executor-contract.json",
  "documents/security/rls-program/production-full-rls-executor-contract.json",
  "infra/terraform/staging-api/lambda/database-role-executor-broker/index.mjs",
  "infra/terraform/staging-api/main.tf",
  "infra/terraform/staging-api/variables.tf",
  "infra/aws/terraform/main.tf",
  "infra/aws/terraform/production-green-stage-a/main.tf",
  "infra/aws/terraform/production-green-stage-a/variables.tf",
  "infra/aws/terraform/production-green-stage-a/versions.tf",
  "infra/aws/terraform/production-green-stage-a/providers.tf",
  "infra/aws/terraform/production-green-stage-a/production-state-backend-prerequisite.json",
  "infra/aws/terraform/production-green-stage-b/release-activation-contract.json",
  "infra/aws/terraform/providers.tf",
  "infra/aws/terraform/variables.tf",
  "infra/aws/terraform/versions.tf",
  "infra/aws/terraform/outputs.tf",
  "infra/aws/terraform/lambda/production-rls-approval-broker/index.mjs",
  "scripts/aws/production-green-stage-b-contract.mjs",
  "scripts/aws/create-production-green-stage-b-approval.mjs",
  "scripts/aws/apply-production-full-rls-release.mjs",
  "scripts/aws/deploy-ecs-service.sh",
  "scripts/aws/publish-ecs-images.sh",
  "scripts/aws/production-credential-source-contract.mjs",
  "scripts/aws/production-credential-source.sh",
  "scripts/smoke-release.mjs",
  "scripts/lib/staging-smoke-totp.mjs",
  ".github/workflows/release-gate.yml",
  ".github/workflows/release-train.yml",
  "backend/src/rls-waves/session-b/b01/b01RefreshRotationFunctions.sql",
  "backend/src/rls-waves/session-b/b01/b01RefreshRotationRollback.sql",
  "backend/src/rls-waves/session-b/b01/authenticatedSessionCapabilityFunctions.sql",
  "backend/src/rls-waves/session-b/b01/authenticatedSessionCapabilityRollback.sql",
  "backend/src/rls-waves/session-b/b02/publicVerificationFunctions.sql",
  "backend/src/rls-waves/session-b/b02/publicVerificationRollback.sql",
  "backend/src/rls-waves/session-a/operationalReadBoundaries.sql",
  "backend/src/rls-waves/session-a/operationalReadBoundariesRollback.sql",
  "backend/src/rls-waves/session-c/c01/administration.sql",
  "backend/src/rls-waves/session-c/c01/administrationRollback.sql",
  "backend/src/rls-waves/session-c/c01/qrSystem.sql",
  "backend/src/rls-waves/session-c/c01/qrSystemRollback.sql",
  ...applicationPathCertificationFamilies.map((family) => family.testFile),
])];

const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const stable = (value) => `${JSON.stringify(value, null, 2)}\n`;

export const calculateCleanRoomSourceContract = (root = cleanRoomRepoRoot) => {
  const inputs = cleanRoomSourcePaths.map((relativePath) => ({
    path: relativePath,
    sha256: sha256(fs.readFileSync(path.join(root, relativePath))),
  }));
  const migrationsRoot = path.join(root, "backend/prisma/migrations");
  const prismaMigrations = fs.readdirSync(migrationsRoot, { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => ({
      name: entry.name,
      sha256: sha256(fs.readFileSync(path.join(migrationsRoot, entry.name, "migration.sql"))),
    }))
    .sort((left, right) => left.name.localeCompare(right.name));
  const sourceContract = { schemaVersion: 1, inputs, prismaMigrations };
  return {
    sourceContract,
    sourceContractSha256: sha256(stable(sourceContract)),
    migrationSetDigest: sha256(stable(prismaMigrations)),
    inputs,
    prismaMigrations,
    prismaSchemaSource: fs.readFileSync(path.join(root, "backend/prisma/schema.prisma"), "utf8"),
  };
};
