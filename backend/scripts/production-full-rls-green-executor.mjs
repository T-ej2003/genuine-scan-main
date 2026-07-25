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

export const PRODUCTION_GREEN = Object.freeze({
  environment: "production",
  region: "eu-west-2",
  administrator: "mscqr_prod_admin",
  maintenanceDatabase: "mscqr_production",
  database: "mscqr_production_rls_green_phase2",
  deploymentId: "phase2",
  rolePrefix: "mscqr_prd_rls_phase2_",
  secretPrefix: "mscqr/production/rls-green/phase2/database-url/",
  hostnamePattern: /(?:production|prod)/i,
  forbiddenHostnamePattern: /staging|stg|dev|local/i,
  receiptBucketPattern: /^mscqr-production-[a-z0-9-]+-artifacts-[0-9]{12}$/,
  confirmations: Object.freeze({
    "full-rls-role-provision": "MSCQR_PRODUCTION_GREEN_PROVISION_RUNTIME_ROLES",
    "full-rls-admin-bootstrap": "MSCQR_PRODUCTION_GREEN_CREATE_AND_BOOTSTRAP_DATABASE",
    "full-rls-admin-ownership": "MSCQR_PRODUCTION_GREEN_INSTALL_OWNERSHIP_GRANTS",
    "full-rls-runtime-policy": "MSCQR_PRODUCTION_GREEN_INSTALL_RUNTIME_POLICIES",
    "full-rls-rollback": "MSCQR_PRODUCTION_GREEN_ROLLBACK_EXACT_PACKAGE",
  }),
});

export const GREEN_MUTATION_CONFIRMATIONS = PRODUCTION_GREEN.confirmations;
export const validateGreenExecutorMode = (mode, confirmation) =>
  validateGreenExecutorModeCore(PRODUCTION_GREEN, mode, confirmation);
export const validateProductionAdministratorUrl = (raw) =>
  validateAdministratorUrlCore(PRODUCTION_GREEN, raw);
export const verifyBoundPackage = (options) => verifyBoundPackageCore(PRODUCTION_GREEN, options);
export const executeProductionGreenMode = (options) => executeFullRlsGreenMode(PRODUCTION_GREEN, options);

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  executeProductionGreenMode().catch(() => {
    process.stderr.write('{"status":"blocked","reason":"production-green-executor-failed"}\n');
    process.exitCode = 1;
  });
}
