#!/usr/bin/env node
"use strict";

const databaseModule = require("../dist/config/database");
const { reissueAccountSetupLink } = require("../dist/rls-waves/session-c/operatorProcedureService");

const prisma = databaseModule.default || databaseModule.prisma;
const readArg = (name) => {
  const flag = `--${name}`;
  const index = process.argv.indexOf(flag);
  return index >= 0 ? String(process.argv[index + 1] || "").trim() : "";
};

const main = async () => {
  if (process.argv.includes("--help") || process.argv.includes("-h")) {
    console.log("Usage: auth:resend-setup-link -- [--apply] --target-user-id UUID --operator-id UUID --approval-id UUID --reason TEXT");
    return;
  }

  const environment = String(process.env.NODE_ENV || "").trim().toLowerCase();
  if (!["development", "staging", "production"].includes(environment)) {
    throw new Error("NODE_ENV must be development, staging, or production.");
  }

  const input = {
    targetUserId: readArg("target-user-id"),
    operatorId: readArg("operator-id"),
    approvalId: readArg("approval-id"),
    reason: readArg("reason"),
    purpose: "operator-account-setup-link-reissue",
    assurance: "operator-approved",
    environment,
  };

  if (!process.argv.includes("--apply")) {
    console.log(JSON.stringify({ ok: true, mode: "dry-run", procedure: "app_ops.reissue_account_setup_link", tokenLogged: false }));
    return;
  }

  const result = await reissueAccountSetupLink(input);
  console.log(JSON.stringify({ ok: true, ...result, tokenLogged: false }));
};

main()
  .catch((error) => {
    console.error("resend password setup link failed:", error instanceof Error ? error.message : "Unknown error");
    process.exitCode = 1;
  })
  .finally(() => prisma.$disconnect());
