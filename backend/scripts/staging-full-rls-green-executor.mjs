#!/usr/bin/env node
import process from "node:process";
import { pathToFileURL } from "node:url";
import {
  GREEN_EXECUTOR_MODES,
  executeFullRlsGreenMode,
  validateAdministratorUrl as validateAdministratorUrlCore,
  validateGreenExecutorMode as validateGreenExecutorModeCore,
  verifyBoundPackage as verifyBoundPackageCore,
} from "./full-rls-green-executor-core.mjs";

export { GREEN_EXECUTOR_MODES };

export const STAGING_GREEN = Object.freeze({
  environment: "staging",
  region: "eu-west-2",
  administrator: "mscqr_staging_admin",
  maintenanceDatabase: "mscqr_staging",
  database: "mscqr_staging_rls_green_phase2",
  deploymentId: "phase2",
  rolePrefix: "mscqr_stg_rls_phase2_",
  secretPrefix: "mscqr/staging/rls-green/phase2/database-url/",
  hostnamePattern: /(?:staging|stg)/i,
  forbiddenHostnamePattern: /prod|production|live/i,
  receiptBucketPattern: /^mscqr-staging-[a-z0-9-]+-artifacts-[0-9]{12}$/,
  confirmations: Object.freeze({
    "full-rls-role-provision": "MSCQR_STAGING_GREEN_PROVISION_RUNTIME_ROLES",
    "full-rls-admin-bootstrap": "MSCQR_STAGING_GREEN_CREATE_AND_BOOTSTRAP_DATABASE",
    "full-rls-admin-ownership": "MSCQR_STAGING_GREEN_INSTALL_OWNERSHIP_GRANTS",
    "full-rls-runtime-policy": "MSCQR_STAGING_GREEN_INSTALL_RUNTIME_POLICIES",
    "full-rls-rollback": "MSCQR_STAGING_GREEN_ROLLBACK_EXACT_PACKAGE",
  }),
});

export const GREEN_MUTATION_CONFIRMATIONS = STAGING_GREEN.confirmations;
export const validateGreenExecutorMode = (mode, confirmation) =>
  validateGreenExecutorModeCore(STAGING_GREEN, mode, confirmation);
export const validateStagingAdministratorUrl = (raw) =>
  validateAdministratorUrlCore(STAGING_GREEN, raw);
export const verifyBoundPackage = (options) => verifyBoundPackageCore(STAGING_GREEN, options);
export const executeStagingGreenMode = (options) => executeFullRlsGreenMode(STAGING_GREEN, options);

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  executeStagingGreenMode().catch(() => {
    process.stderr.write('{"status":"blocked","reason":"staging-green-executor-failed"}\n');
    process.exitCode = 1;
  });
}
