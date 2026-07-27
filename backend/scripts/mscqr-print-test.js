#!/usr/bin/env node
const path = require("path");
const dotenv = require("dotenv");

dotenv.config();
dotenv.config({ path: path.resolve(__dirname, "../.env") });

const prisma = require("../dist/config/database").default;
const { runPrintDiagnostic } = require("../dist/rls-waves/session-c/operatorProcedureService");

const CONFIRMATION_PHRASE = "MSCQR_RUN_PRINT_DIAGNOSTIC";

const args = new Map();
for (let i = 2; i < process.argv.length; i += 1) {
  const arg = process.argv[i];
  if (!arg.startsWith("--")) continue;
  const key = arg.slice(2);
  const next = process.argv[i + 1];
  if (!next || next.startsWith("--")) {
    args.set(key, true);
  } else {
    args.set(key, next);
    i += 1;
  }
}

const required = (key) => {
  const value = args.get(key);
  if (typeof value !== "string" || !value.trim()) throw new Error(`Missing required --${key}`);
  return value.trim();
};

const main = async () => {
  const environment = String(process.env.NODE_ENV || "").trim().toLowerCase();
  if (!new Set(["development", "staging"]).has(environment)) {
    throw new Error("Print diagnostic is available only in development or staging.");
  }
  if (String(process.env.MSCQR_PRINT_DIAGNOSTIC_CONFIRM || "").trim() !== CONFIRMATION_PHRASE) {
    throw new Error(`MSCQR_PRINT_DIAGNOSTIC_CONFIRM must equal ${CONFIRMATION_PHRASE}.`);
  }
  const unsupported = [...args.keys()].filter((key) => !["batch", "operator-id", "licensee-id"].includes(key));
  if (unsupported.length) {
    throw new Error(`Unsupported argument: --${unsupported[0]}`);
  }

  const batchId = required("batch");
  const result = await runPrintDiagnostic({
    batchId,
    operatorId: required("operator-id"),
    licenseeId: required("licensee-id"),
    purpose: "operator-print-diagnostic",
    assurance: "operator-approved",
    environment,
  });

  console.log(
    JSON.stringify(
      {
        ok: true,
        ...result,
        qrPayloadsReturned: false,
      },
      null,
      2
    )
  );
};

main()
  .catch((error) => {
    console.error(error?.message || error);
    process.exitCode = 1;
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
