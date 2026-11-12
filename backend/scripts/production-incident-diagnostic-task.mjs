#!/usr/bin/env node
// One-time, fixed-scope task. The reviewed launcher must verify the independent approval and exact task definition before registration.
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { S3Client, PutObjectCommand, GetObjectCommand } from "@aws-sdk/client-s3";
import { STSClient, GetCallerIdentityCommand } from "@aws-sdk/client-sts";
import { PrismaClient } from "@prisma/client";
import { INCIDENT_DATABASE, INCIDENT_ROLE, INCIDENT_SOURCE_SHA } from "./production-incident-diagnostic-queries.mjs";
import { buildIncidentDiagnosticSql } from "./production-incident-diagnostic-sql.mjs";
import { ALLOWED_ENVIRONMENT_NAMES } from "./production-read-only-database-config.mjs";

const account = "368992683803";
const region = "eu-west-2";
const bucket = "mscqr-prod-euw2-artifacts-368992683803-eu-west-2-an";
const applicationName = "mscqr-incident-20261112-read";
const roleArnPrefix = `arn:aws:sts::${account}:assumed-role/mscqr-production-full-rls-green-read-only-canary-task/`;
const digest = (value) => createHash("sha256").update(value).digest("hex");
const json = (value) => `${JSON.stringify(value)}\n`;
const sha = /^[a-f0-9]{64}$/;
const databaseHostname = "mscqr-production-rls-green-phase2.c3ewey6o6mq5.eu-west-2.rds.amazonaws.com";

export function validateIncidentTaskInput({ env, argv, now = new Date() }) {
  if (argv.length || Object.keys(env).some((key) => !["MSCQR_INCIDENT_DIAGNOSTIC_AUTHORIZATION", "MSCQR_INCIDENT_ADMIN_PASSWORD"].includes(key) && !ALLOWED_ENVIRONMENT_NAMES.has(key))
      || env.NODE_ENV !== "production" || env.RUN_DB_MIGRATIONS_ON_START !== "false"
      || env.AWS_REGION !== region || env.AWS_DEFAULT_REGION !== region || env.AWS_EXECUTION_ENV !== "AWS_ECS_FARGATE") throw new Error("Task runtime is outside the reviewed contract.");
  const authorization = JSON.parse(String(env.MSCQR_INCIDENT_DIAGNOSTIC_AUTHORIZATION || "null"));
  if (!authorization || Object.keys(authorization).sort().join(",") !== ["account", "approvalEvidenceSha256", "database", "diagnosticSourceSha", "executionId", "expiresAt", "issuedAt", "provisionSha256", "querySha256", "teardownSha256", "region", "sourceSha"].sort().join(",")
      || authorization.account !== account || authorization.region !== region || authorization.sourceSha !== INCIDENT_SOURCE_SHA
      || authorization.database !== INCIDENT_DATABASE || authorization.diagnosticSourceSha !== env.GIT_SHA
      || !/^[a-f0-9]{40}$/.test(env.GIT_SHA || "") || env.RELEASE_GIT_SHA !== env.GIT_SHA
      || !sha.test(authorization.approvalEvidenceSha256) || !env.MSCQR_INCIDENT_ADMIN_PASSWORD
      || Date.parse(authorization.issuedAt) > now.getTime()
      || now.getTime() >= Date.parse(authorization.expiresAt)) throw new Error("Diagnostic authorization identity or expiry is invalid.");
  const sql = buildIncidentDiagnosticSql(authorization);
  if (authorization.provisionSha256 !== digest(sql.provision) || authorization.querySha256 !== digest(sql.query)
      || authorization.teardownSha256 !== digest(sql.teardown)) throw new Error("Diagnostic SQL digest is not bound to the authorization.");
  const url = new URL(String(env.RLS_CANARY_DATABASE_URL || ""));
  if (!/^postgres(?:ql)?:$/.test(url.protocol) || !url.password || url.username !== "mscqr_prod_rls_canary_read"
      || url.hostname !== databaseHostname
      || url.pathname !== `/${INCIDENT_DATABASE}` || url.hash || url.searchParams.size !== 2
      || url.searchParams.get("sslmode") !== "require"
      || url.searchParams.get("application_name") !== "mscqr-production-green-read-only-rls-canary") throw new Error("Diagnostic database binding is invalid.");
  url.searchParams.set("application_name", applicationName);
  return { authorization, sql, databaseUrl: url.toString() };
}

export function runScopedSql(sql, password) {
  execFileSync("psql", ["-X", "-w", "-q", "-v", "ON_ERROR_STOP=1", "-h", databaseHostname,
    "-U", "mscqr_prod_admin", "-d", INCIDENT_DATABASE], { input: sql, encoding: "utf8", timeout: 15000,
    maxBuffer: 4096, env: { ...process.env, PGPASSWORD: password, PGSSLMODE: "require", PGCONNECT_TIMEOUT: "3" } });
}

export async function runIncidentTask({ env = process.env, argv = process.argv.slice(2), now = () => new Date(), s3, sts,
  createClient, executeSql = runScopedSql, imageSource = () => JSON.parse(readFileSync("/app/image-source.json", "utf8")) } = {}) {
  const { authorization, databaseUrl, sql } = validateIncidentTaskInput({ env, argv, now: now() });
  if (JSON.stringify(imageSource()) !== JSON.stringify({ gitSha: authorization.diagnosticSourceSha })) throw new Error("Diagnostic image source is invalid.");
  const s3Client = s3 ?? new S3Client({ region, maxAttempts: 1 });
  const stsClient = sts ?? new STSClient({ region, maxAttempts: 1 });
  const identity = await stsClient.send(new GetCallerIdentityCommand({}));
  if (identity.Account !== account || !String(identity.Arn || "").startsWith(roleArnPrefix)) throw new Error("Diagnostic task role identity is invalid.");
  const taskInputSha256 = digest(json(authorization));
  const prefix = `production-incident-20261112/${authorization.executionId}/`;
  const reserve = json({ kind: "INCIDENT_DIAGNOSTIC_RESERVED", executionId: authorization.executionId,
    sourceSha: INCIDENT_SOURCE_SHA, diagnosticSourceSha: authorization.diagnosticSourceSha,
    taskInputSha256, approvalEvidenceSha256: authorization.approvalEvidenceSha256, at: now().toISOString() });
  const putOnce = async (key, body) => {
    await s3Client.send(new PutObjectCommand({ Bucket: bucket, Key: key, Body: body, ContentType: "application/json",
      ServerSideEncryption: "AES256", IfNoneMatch: "*" }));
    const readback = await s3Client.send(new GetObjectCommand({ Bucket: bucket, Key: key }));
    if (Number(readback.ContentLength) !== Buffer.byteLength(body)
        || !Buffer.from(await readback.Body.transformToByteArray()).equals(Buffer.from(body))) throw new Error("Diagnostic journal readback mismatch.");
    return digest(body);
  };
  const reservationSha256 = await putOnce(`${prefix}reservation.json`, reserve);
  let client;
  let status = "FAILED_OR_INDETERMINATE";
  let evidence = null;
  let provisionAttempted = false;
  let provisionCompleted = false;
  let primaryError;
  let primaryPhase;
  let cleanupError;
  try {
    provisionAttempted = true;
    await executeSql(sql.provision, env.MSCQR_INCIDENT_ADMIN_PASSWORD);
    provisionCompleted = true;
    client = createClient?.(databaseUrl) ?? new PrismaClient({ datasources: { db: { url: databaseUrl } } });
    evidence = await client.$transaction(async (tx) => {
      for (const statement of sql.queryStatements.slice(0, 3)) await tx.$executeRawUnsafe(statement);
      await tx.$queryRawUnsafe(sql.queryStatements[3]);
      await tx.$queryRawUnsafe(sql.queryStatements[4]);
      const [row] = await tx.$queryRawUnsafe(sql.queryStatements[5]);
      const result = row?.evidence;
      if (!result || result.identity?.[0]?.role !== "mscqr_prd_rls_phase2_owner" || result.identity?.[0]?.session_role !== INCIDENT_ROLE
          || result.identity?.[0]?.database_name !== INCIDENT_DATABASE || result.identity?.[0]?.read_only !== "on"
          || result.rls?.length !== 12 || result.rls.some((entry) => !entry.rls_enabled || !entry.force_rls)) throw new Error("Diagnostic database identity, grants, or FORCE RLS proof failed.");
      const bytes = json(result);
      if (Buffer.byteLength(bytes) > 64 * 1024) throw new Error("Diagnostic output exceeds reviewed bound.");
      return { result, resultSha256: digest(bytes) };
    }, { maxWait: 2000, timeout: 15000 });
  } catch (error) {
    primaryError = error;
    primaryPhase = provisionCompleted ? "READ" : "PROVISION";
  } finally {
    try { await client?.$disconnect(); }
    catch (error) { primaryError ??= error; primaryPhase ??= "DISCONNECT"; }
    if (provisionAttempted) {
      try { await executeSql(sql.teardown, env.MSCQR_INCIDENT_ADMIN_PASSWORD); if (evidence) status = "COMPLETE"; }
      catch (error) { cleanupError = error; evidence = null; }
    }
  }
  if (primaryError || cleanupError) { status = "FAILED_OR_INDETERMINATE"; evidence = null; }
  const terminal = json({ kind: "INCIDENT_DIAGNOSTIC_TERMINAL", status, executionId: authorization.executionId,
    sourceSha: authorization.sourceSha, diagnosticSourceSha: authorization.diagnosticSourceSha,
    database: INCIDENT_DATABASE, databaseRole: INCIDENT_ROLE, taskRoleArn: identity.Arn,
    provisionSha256: authorization.provisionSha256, querySha256: authorization.querySha256,
    teardownSha256: authorization.teardownSha256, taskInputSha256, reservationSha256,
    failurePhases: [primaryPhase, cleanupError && "CLEANUP"].filter(Boolean),
    rowCounts: evidence ? Object.fromEntries(Object.entries(evidence.result).map(([key, value]) => [key, value.length])) : null,
    at: now().toISOString(), evidence });
  if (Buffer.byteLength(terminal) > 70 * 1024) throw new Error("Diagnostic terminal record exceeds reviewed bound.");
  let receiptSha256;
  try { receiptSha256 = await putOnce(`${prefix}terminal.json`, terminal); }
  catch (receiptError) {
    const errors = [primaryError, cleanupError, receiptError].filter(Boolean);
    if (errors.length > 1) throw new AggregateError(errors, "Incident diagnostic and terminal receipt failed");
    throw receiptError;
  }
  if (primaryError && cleanupError) throw new AggregateError([primaryError, cleanupError], "Incident diagnostic and cleanup failed");
  if (primaryError || cleanupError) throw primaryError || cleanupError;
  return { status, executionId: authorization.executionId, reservationSha256, receiptSha256, terminalKey: `${prefix}terminal.json` };
}

if (import.meta.url === new URL(process.argv[1], "file:").href) {
  runIncidentTask().then((result) => { process.stdout.write(json(result)); process.exitCode = result.status === "COMPLETE" ? 0 : 1; })
    .catch(() => { process.stdout.write(json({ status: "BLOCKED_OR_INDETERMINATE" })); process.exitCode = 1; });
}
