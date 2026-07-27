import path from "path";

import dotenv from "dotenv";

dotenv.config();
dotenv.config({ path: path.resolve(__dirname, "../.env") });

import prisma from "../src/config/database";
import { resetAccountMfaBreakGlass } from "../src/rls-waves/session-c/operatorProcedureService";

const CONFIRMATION_PHRASE = "MSCQR_EXECUTE_DUAL_APPROVED_MFA_RESET";

const readArg = (name: string) => {
  const flag = `--${name}`;
  const index = process.argv.findIndex((entry) => entry === flag);
  if (index < 0) return "";
  return String(process.argv[index + 1] || "").trim();
};

const run = async () => {
  if (String(process.env.NODE_ENV || "").trim().toLowerCase() !== "production") {
    throw new Error("Break-glass MFA reset is available only through the production break-glass identity.");
  }
  if (String(process.env.MSCQR_BREAK_GLASS_CONFIRM || "").trim() !== CONFIRMATION_PHRASE) {
    throw new Error(`MSCQR_BREAK_GLASS_CONFIRM must equal ${CONFIRMATION_PHRASE}.`);
  }

  const result = await resetAccountMfaBreakGlass({
    targetUserId: readArg("target-user-id"),
    executorId: readArg("executor-id"),
    reason: readArg("reason"),
    approvalId: readArg("approval-id"),
    purpose: "dual-approved-break-glass-mfa-reset",
    assurance: "dual-approved-break-glass",
    environment: "production",
  });

  console.log(
    JSON.stringify({
      ok: true,
      operationId: result.operationId,
      status: result.status,
      affectedCount: result.affectedCount,
      auditEventId: result.auditEventId,
      targetPrinted: false,
    })
  );
};

run()
  .catch((error) => {
    console.error(error);
    process.exitCode = 1;
  })
  .finally(async () => {
    await prisma.$disconnect().catch(() => undefined);
  });
