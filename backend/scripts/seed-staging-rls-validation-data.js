#!/usr/bin/env node
"use strict";

const ENABLED_ENV = "STAGING_RLS_SEED_ENABLED";
const CONFIRM_ENV = "STAGING_RLS_SEED_CONFIRM";
const CONFIRMATION_PHRASE = "MSCQR_CREATE_STAGING_RLS_VALIDATION_DATA";
const FIXTURE_ID = "00000000-0000-4302-8000-000000000001";

const isTruthy = (value) => ["1", "true", "yes", "on"].includes(String(value || "").trim().toLowerCase());

const readConfig = (env = process.env) => {
  if (!isTruthy(env[ENABLED_ENV])) throw new Error(`${ENABLED_ENV}=true is required.`);
  if (String(env[CONFIRM_ENV] || "").trim() !== CONFIRMATION_PHRASE) {
    throw new Error(`${CONFIRM_ENV} must equal ${CONFIRMATION_PHRASE}.`);
  }
  if (String(env.STAGING_RLS_SEED_ENVIRONMENT || "").trim().toLowerCase() !== "staging") {
    throw new Error("STAGING_RLS_SEED_ENVIRONMENT must equal staging.");
  }

  let databaseUrl;
  try {
    databaseUrl = new URL(String(env.DATABASE_URL || ""));
  } catch {
    throw new Error("DATABASE_URL must be a valid PostgreSQL URL; the value was not printed.");
  }
  const fingerprint = `${databaseUrl.hostname}/${databaseUrl.pathname}/${databaseUrl.username}`.toLowerCase();
  if (!["postgres:", "postgresql:"].includes(databaseUrl.protocol) || /(^|[-_/])prod(uction)?([-_/]|$)/.test(fingerprint)) {
    throw new Error("Refusing non-staging or production-looking DATABASE_URL.");
  }
  if (!/(staging|rls_wave_c|localhost|127\.0\.0\.1)/.test(fingerprint)) {
    throw new Error("DATABASE_URL must identify the reviewed staging or local Session C database.");
  }

  return {
    fixtureId: FIXTURE_ID,
    tenantKey: "mscqr_staging_rls_validation",
    operatorId: String(env.STAGING_RLS_SEED_OPERATOR_ID || "").trim(),
    approvalId: String(env.STAGING_RLS_SEED_APPROVAL_ID || "").trim(),
    purpose: "operator-staging-rls-validation-fixture",
    assurance: "operator-approved",
    environment: "staging",
  };
};

const seedStagingRlsValidationData = async (config, db) => {
  const { prepareRlsValidationFixture } = require("../dist/rls-waves/session-c/operatorProcedureService");
  return prepareRlsValidationFixture(config, db);
};

const main = async () => {
  if (process.argv.includes("--help")) {
    console.log(`Safety contract: ${ENABLED_ENV}=true, ${CONFIRM_ENV}=${CONFIRMATION_PHRASE}, exact staging database, operator and approval IDs.`);
    return;
  }
  const databaseModule = require("../dist/config/database");
  const prisma = databaseModule.default || databaseModule.prisma;
  try {
    const result = await seedStagingRlsValidationData(readConfig(), prisma);
    console.log(JSON.stringify({ ok: true, ...result, databaseUrlPrinted: false, authTokenPrinted: false }));
  } finally {
    await prisma.$disconnect();
  }
};

if (require.main === module) {
  main().catch((error) => {
    console.log(JSON.stringify({ ok: false, errorCode: "STAGING_RLS_VALIDATION_SEED_REFUSED", diagnostic: error instanceof Error ? error.message : "Unknown error", databaseUrlPrinted: false, authTokenPrinted: false }));
    process.exitCode = 1;
  });
}

module.exports = { CONFIRMATION_PHRASE, FIXTURE_ID, readConfig, seedStagingRlsValidationData };
