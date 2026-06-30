import { Prisma } from "@prisma/client";

import prisma from "../config/database";
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

type ListScopedManufacturerPrintersReadParams = {
  user: AuthenticatedSessionClaims;
  userId: string;
  orgId?: string | null;
  licenseeId?: string | null;
  licenseeIds?: string[] | null;
  includeInactive?: boolean;
};

const loadScopedManufacturerPrintersReadPayload = (
  params: ListScopedManufacturerPrintersReadParams,
  db?: Prisma.TransactionClient
) =>
  listRegisteredPrintersForManufacturer({
    userId: params.userId,
    orgId: params.orgId,
    licenseeId: params.licenseeId,
    licenseeIds: params.licenseeIds,
    includeInactive: params.includeInactive,
    db,
  });

export const listScopedManufacturerPrintersReadPayload = async (
  params: ListScopedManufacturerPrintersReadParams
) => {
  const flagEnabled = isStagingRlsManufacturerPrintersReadEnabled();
  if (flagEnabled) {
    const startedAt = process.hrtime.bigint();
    const contextClass = classifyStagingRlsManufacturerPrintersReadContext(params.user);
    try {
      const rows = await withStagingRlsBatchReadTransaction(prisma, params.user, (tx) =>
        loadScopedManufacturerPrintersReadPayload(params, tx)
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
