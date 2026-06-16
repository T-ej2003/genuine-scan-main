#!/usr/bin/env node
const path = require("path");
const dotenv = require("dotenv");

dotenv.config();
dotenv.config({ path: path.resolve(__dirname, "../.env") });

const prisma = require("../dist/config/database").default;
const {
  findPrintLifecycleDriftBatches,
  reconcileBatchPrintLifecycle,
} = require("../dist/services/batchPrintLifecycleReconciliationService");

const readArg = (name) => {
  const index = process.argv.findIndex((entry) => entry === `--${name}`);
  return index >= 0 ? String(process.argv[index + 1] || "").trim() : "";
};
const hasFlag = (name) => process.argv.includes(`--${name}`);

const run = async () => {
  const apply = hasFlag("apply");
  const json = hasFlag("json");
  const batchId = readArg("batchId") || undefined;
  const licenseeId = readArg("licenseeId") || undefined;
  const manufacturerId = readArg("manufacturerId") || undefined;
  const limitRaw = Number(readArg("limit") || "100");
  const limit = Number.isFinite(limitRaw) && limitRaw > 0 ? Math.floor(limitRaw) : 100;
  const candidates = await findPrintLifecycleDriftBatches({ batchId, licenseeId, manufacturerId, limit });
  const rows = [];

  for (const candidate of candidates) {
    const applied = apply
      ? await prisma.$transaction((tx) =>
          reconcileBatchPrintLifecycle({
            batchId: candidate.id,
            actorUserId: null,
            apply: true,
            reason: "controlled_production_backfill",
            tx,
          })
        )
      : candidate.reconciliation;
    rows.push({
      batchId: candidate.id,
      licenseeId: candidate.licenseeId,
      manufacturerId: candidate.manufacturerId,
      beforeState: applied.beforeState,
      afterState: applied.afterState,
      targetState: applied.targetState,
      mutated: applied.mutated,
      printedAt: candidate.printedAt,
      totalCodes: candidate.totalCodes,
      evidence: applied.evidence,
    });
  }

  const result = {
    mode: apply ? "apply" : "dry-run",
    scannedCandidates: candidates.length,
    mutated: rows.filter((row) => row.mutated).length,
    filters: { batchId: batchId || null, licenseeId: licenseeId || null, manufacturerId: manufacturerId || null, limit },
    rows,
  };

  if (json) {
    console.log(JSON.stringify(result, null, 2));
    return;
  }
  console.log(`Batch print lifecycle reconciliation ${result.mode} completed.`);
  console.log(`Candidates: ${result.scannedCandidates}`);
  console.log(`Mutated: ${result.mutated}`);
  for (const row of rows) {
    console.log(
      [
        `- ${row.batchId}`,
        `licensee=${row.licenseeId}`,
        `manufacturer=${row.manufacturerId || "none"}`,
        `${row.beforeState}->${row.afterState}`,
        `target=${row.targetState || "none"}`,
        `printedQr=${row.evidence.printedQrCount}`,
        `confirmedJobs=${row.evidence.confirmedPrintJobCount}`,
        `completedSessions=${row.evidence.completedPrintSessionCount}`,
      ].join(" ")
    );
  }
};

run()
  .catch((error) => {
    console.error("Batch print lifecycle reconciliation failed", error);
    process.exitCode = 1;
  })
  .finally(async () => {
    await prisma.$disconnect().catch(() => undefined);
  });
