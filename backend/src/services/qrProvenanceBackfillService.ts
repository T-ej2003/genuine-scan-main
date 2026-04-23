import prisma from "../config/database";

type HistoricalProvenanceAssessment = {
  qrCodeId: string;
  code: string | null;
  currentIssuanceMode: string;
  nextIssuanceMode: string;
  nextCustomerVerifiableAt: string | null;
  shouldUpdate: boolean;
  disposition:
    | "UPGRADE_GOVERNED_PRINT"
    | "REPAIR_GOVERNED_READY_AT"
    | "LEAVE_UNKNOWN_HISTORICAL"
    | "SKIP_EXISTING_PROVENANCE";
  evidence: string[];
};

type BackfillHistoricalQrProvenanceOptions = {
  licenseeId?: string;
  limit?: number;
  dryRun?: boolean;
};

const normalizeIssuanceMode = (value: unknown) => {
  const normalized = String(value || "LEGACY_UNSPECIFIED").trim().toUpperCase();
  return normalized || "LEGACY_UNSPECIFIED";
};
const isHistoricalUnknownIssuanceMode = (issuanceMode: string) => issuanceMode === "LEGACY_UNSPECIFIED";

const toDate = (value: unknown) => {
  if (!value) return null;
  const parsed = value instanceof Date ? value : new Date(String(value));
  return Number.isFinite(parsed.getTime()) ? parsed : null;
};

const deriveGovernedEvidenceTimestamp = (qrCode: any) => {
  const candidates = [
    toDate(qrCode?.customerVerifiableAt),
    toDate(qrCode?.printedAt),
    toDate(qrCode?.printJob?.confirmedAt),
    toDate(qrCode?.printJob?.printSession?.completedAt),
    toDate(qrCode?.batch?.printedAt),
  ].filter(Boolean) as Date[];

  if (!candidates.length) return null;
  return candidates.sort((a, b) => a.getTime() - b.getTime())[0];
};

export const assessHistoricalQrProvenance = (qrCode: any): HistoricalProvenanceAssessment => {
  const issuanceMode = normalizeIssuanceMode(qrCode?.issuanceMode);
  const code = String(qrCode?.code || "").trim() || null;
  const evidence: string[] = [];
  const governedEvidenceTimestamp = deriveGovernedEvidenceTimestamp(qrCode);
  const printJobStatus = String(qrCode?.printJob?.status || "").trim().toUpperCase();
  const pipelineState = String(qrCode?.printJob?.pipelineState || "").trim().toUpperCase();
  const printSessionStatus = String(qrCode?.printJob?.printSession?.status || "").trim().toUpperCase();

  if (qrCode?.printJobId) evidence.push("print_job_attached");
  if (printJobStatus === "CONFIRMED") evidence.push("print_job_confirmed");
  if (pipelineState === "PRINT_CONFIRMED") evidence.push("print_pipeline_confirmed");
  if (printSessionStatus === "COMPLETED") evidence.push("print_session_completed");
  if (toDate(qrCode?.printedAt)) evidence.push("qr_printed_at");
  if (toDate(qrCode?.customerVerifiableAt)) evidence.push("customer_verifiable_at");
  if (toDate(qrCode?.batch?.printedAt)) evidence.push("batch_printed_at");

  const governedEvidenceStrong =
    Boolean(qrCode?.printJobId) &&
    (evidence.includes("print_job_confirmed") ||
      evidence.includes("print_pipeline_confirmed") ||
      evidence.includes("print_session_completed") ||
      evidence.includes("qr_printed_at") ||
      evidence.includes("customer_verifiable_at"));

  if (issuanceMode === "GOVERNED_PRINT") {
    if (!toDate(qrCode?.customerVerifiableAt) && governedEvidenceTimestamp) {
      return {
        qrCodeId: String(qrCode?.id || "").trim(),
        code,
        currentIssuanceMode: issuanceMode,
        nextIssuanceMode: "GOVERNED_PRINT",
        nextCustomerVerifiableAt: governedEvidenceTimestamp.toISOString(),
        shouldUpdate: true,
        disposition: "REPAIR_GOVERNED_READY_AT",
        evidence,
      };
    }

    return {
      qrCodeId: String(qrCode?.id || "").trim(),
      code,
      currentIssuanceMode: issuanceMode,
      nextIssuanceMode: issuanceMode,
      nextCustomerVerifiableAt: toDate(qrCode?.customerVerifiableAt)?.toISOString() || null,
      shouldUpdate: false,
      disposition: "SKIP_EXISTING_PROVENANCE",
      evidence,
    };
  }

  if (!isHistoricalUnknownIssuanceMode(issuanceMode)) {
    return {
      qrCodeId: String(qrCode?.id || "").trim(),
      code,
      currentIssuanceMode: issuanceMode,
      nextIssuanceMode: issuanceMode,
      nextCustomerVerifiableAt: toDate(qrCode?.customerVerifiableAt)?.toISOString() || null,
      shouldUpdate: false,
      disposition: "SKIP_EXISTING_PROVENANCE",
      evidence,
    };
  }

  if (governedEvidenceStrong && governedEvidenceTimestamp) {
    return {
      qrCodeId: String(qrCode?.id || "").trim(),
      code,
      currentIssuanceMode: issuanceMode,
      nextIssuanceMode: "GOVERNED_PRINT",
      nextCustomerVerifiableAt: governedEvidenceTimestamp.toISOString(),
      shouldUpdate: true,
      disposition: "UPGRADE_GOVERNED_PRINT",
      evidence,
    };
  }

  return {
    qrCodeId: String(qrCode?.id || "").trim(),
    code,
    currentIssuanceMode: issuanceMode,
    nextIssuanceMode: issuanceMode,
    nextCustomerVerifiableAt: toDate(qrCode?.customerVerifiableAt)?.toISOString() || null,
    shouldUpdate: false,
    disposition: isHistoricalUnknownIssuanceMode(issuanceMode) ? "LEAVE_UNKNOWN_HISTORICAL" : "SKIP_EXISTING_PROVENANCE",
    evidence,
  };
};

export const backfillHistoricalQrProvenance = async (opts: BackfillHistoricalQrProvenanceOptions = {}) => {
  const dryRun = opts.dryRun !== false;
  const limit = Math.max(1, Math.min(opts.limit || 1000, 10000));
  const where: Record<string, unknown> = {
    OR: [
      { issuanceMode: "LEGACY_UNSPECIFIED" },
      {
        AND: [{ issuanceMode: "GOVERNED_PRINT" }, { customerVerifiableAt: null }],
      },
    ],
  };
  if (opts.licenseeId) where.licenseeId = opts.licenseeId;

  const candidates = await prisma.qRCode.findMany({
    where,
    orderBy: [{ createdAt: "asc" }, { id: "asc" }],
    take: limit,
    include: {
      batch: {
        select: {
          printedAt: true,
        },
      },
      printJob: {
        select: {
          confirmedAt: true,
          status: true,
          pipelineState: true,
          printSession: {
            select: {
              completedAt: true,
              status: true,
            },
          },
        },
      },
    },
  });

  const assessed = candidates.map((qrCode) => assessHistoricalQrProvenance(qrCode));
  const actionable = assessed.filter((entry) => entry.shouldUpdate);

  if (!dryRun) {
    for (const assessment of actionable) {
      await prisma.qRCode.updateMany({
        where: {
          id: assessment.qrCodeId,
          issuanceMode: assessment.currentIssuanceMode,
        },
        data: {
          issuanceMode: assessment.nextIssuanceMode,
          customerVerifiableAt: assessment.nextCustomerVerifiableAt ? new Date(assessment.nextCustomerVerifiableAt) : undefined,
        },
      });
    }
  }

  return {
    dryRun,
    scanned: assessed.length,
    actionable: actionable.length,
    upgradedGovernedPrint: assessed.filter((entry) => entry.disposition === "UPGRADE_GOVERNED_PRINT").length,
    repairedGovernedReadyAt: assessed.filter((entry) => entry.disposition === "REPAIR_GOVERNED_READY_AT").length,
    leftUnknownHistorical: assessed.filter((entry) => entry.disposition === "LEAVE_UNKNOWN_HISTORICAL").length,
    skippedExistingProvenance: assessed.filter((entry) => entry.disposition === "SKIP_EXISTING_PROVENANCE").length,
    assessments: assessed,
  };
};
