import { RlsReadTransactionClient, RlsReadTransactionRunner } from "../config/rlsReadDatabase";
import { AuthenticatedSessionClaims } from "../types";
import {
  isStagingRlsManufacturerPrintersReadEnabled,
  withStagingRlsBatchReadTransaction,
} from "../lib/stagingRlsBatchReadContext";
import { listRegisteredPrintersForManufacturer } from "./printerRegistryService";
import {
  categorizeStagingRlsManufacturerPrintersReadFailure,
  classifyStagingRlsManufacturerPrintersReadContext,
  recordStagingRlsManufacturerPrintersReadProof,
} from "../observability/stagingRlsManufacturerPrintersReadProof";
import { isManufacturerRole, resolveAccessibleLicenseeIdsForUser } from "./manufacturerScopeService";

type ListScopedManufacturerPrintersReadParams = {
  user: AuthenticatedSessionClaims;
  userId?: string;
  orgId?: string | null;
  licenseeId?: string | null;
  licenseeIds?: string[] | null;
  includeInactive?: boolean;
};

const resolvePrinterReadContext = (params: ListScopedManufacturerPrintersReadParams) => ({
  userId: params.userId || params.user.userId,
  orgId: params.orgId === undefined ? params.user.orgId || null : params.orgId,
  licenseeId: params.licenseeId ?? null,
});

const resolveLicenseeIdsForPrinterRead = async (
  params: ListScopedManufacturerPrintersReadParams,
  db?: RlsReadTransactionClient
) => {
  if (Array.isArray(params.licenseeIds)) return params.licenseeIds;
  if (!isManufacturerRole(params.user.role)) return params.licenseeIds ?? null;
  if (!db) return resolveAccessibleLicenseeIdsForUser(params.user);
  return resolveAccessibleLicenseeIdsForUser(params.user, db);
};

const loadScopedManufacturerPrintersReadPayload = async (
  params: ListScopedManufacturerPrintersReadParams,
  db?: RlsReadTransactionClient
) => {
  const readContext = resolvePrinterReadContext(params);
  const licenseeIds = await resolveLicenseeIdsForPrinterRead(params, db);

  return listRegisteredPrintersForManufacturer({
    userId: readContext.userId,
    orgId: readContext.orgId,
    licenseeId: readContext.licenseeId,
    licenseeIds,
    includeInactive: params.includeInactive,
    db,
  });
};

export const listScopedManufacturerPrintersReadPayload = async (
  params: ListScopedManufacturerPrintersReadParams,
  dependencies: { transactionRunner?: RlsReadTransactionRunner } = {}
) => {
  const flagEnabled = isStagingRlsManufacturerPrintersReadEnabled();
  if (flagEnabled) {
    const startedAt = process.hrtime.bigint();
    const contextClass = classifyStagingRlsManufacturerPrintersReadContext(params.user);
    try {
      const rows = await withStagingRlsBatchReadTransaction(
        params.user,
        (tx) => loadScopedManufacturerPrintersReadPayload(params, tx),
        dependencies
      );
      recordStagingRlsManufacturerPrintersReadProof({
        flagEnabled,
        contextClass,
        durationMs: Number(process.hrtime.bigint() - startedAt) / 1_000_000,
        rowCount: Array.isArray(rows) ? rows.length : 0,
        success: true,
      });
      return rows;
    } catch (error) {
      recordStagingRlsManufacturerPrintersReadProof({
        flagEnabled,
        contextClass,
        durationMs: Number(process.hrtime.bigint() - startedAt) / 1_000_000,
        rowCount: 0,
        success: false,
        failureCategory: categorizeStagingRlsManufacturerPrintersReadFailure(error),
      });
      throw error;
    }
  }

  return loadScopedManufacturerPrintersReadPayload(params);
};
