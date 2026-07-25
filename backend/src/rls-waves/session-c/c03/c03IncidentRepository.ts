import { Prisma } from "@prisma/client";

import type { C03VerifiedDbContext } from "./c03ActorBoundary";

type IncidentDb = Pick<Prisma.TransactionClient, "$queryRaw">;
type JsonRow = { result: Prisma.JsonValue };

const json = (value: unknown) => JSON.stringify(value ?? {});

const requiredObject = <T>(rows: JsonRow[], operation: string): T => {
  if (rows.length !== 1) {
    throw new Error(`${operation} returned an invalid database result`);
  }
  const result = rows[0]?.result;
  if (!result || typeof result !== "object" || Array.isArray(result)) {
    throw new Error(`${operation} returned an invalid database result`);
  }
  return result as T;
};

export const computeIncidentSpamSignalInTransaction = async (
  tx: IncidentDb,
  qrProof: string,
  contactHashes: Record<string, unknown>
) => {
  const rows = await tx.$queryRaw<Array<{ suspectedSpam: boolean }>>`
    SELECT app_rls.c03_compute_incident_spam_signal(
      ${qrProof},
      ${json(contactHashes)}::jsonb
    ) AS "suspectedSpam"
  `;
  if (rows.length !== 1 || typeof rows[0].suspectedSpam !== "boolean") {
    throw new Error("compute incident spam signal returned an invalid database result");
  }
  return rows[0].suspectedSpam;
};

export const computeIncidentSeverityInTransaction = async (
  tx: IncidentDb,
  qrProof: string,
  input: Record<string, unknown>
) => {
  const rows = await tx.$queryRaw<Array<{ severity: string }>>`
    SELECT app_rls.c03_compute_incident_severity(
      ${qrProof},
      ${json(input)}::jsonb
    ) AS severity
  `;
  const severity = String(rows[0]?.severity || "");
  if (rows.length !== 1 || !["LOW", "MEDIUM", "HIGH", "CRITICAL"].includes(severity)) {
    throw new Error("compute incident severity returned an invalid database result");
  }
  return severity;
};

export const createPublicIncidentReportInTransaction = async <T>(
  tx: IncidentDb,
  input: {
    qrProof: string;
    report: Record<string, unknown>;
    uploads: Array<Record<string, unknown>>;
    idempotencyKey: string;
  }
) =>
  requiredObject<T>(
    await tx.$queryRaw<JsonRow[]>`
      SELECT app_rls.c03_create_public_incident_report(
        ${input.qrProof},
        ${json(input.report)}::jsonb,
        ${json(input.uploads)}::jsonb,
        ${input.idempotencyKey}
      ) AS result
    `,
    "create public incident report"
  );

export const recordIncidentEventInTransaction = async <T>(
  tx: IncidentDb,
  incidentId: string,
  eventType: string,
  eventPayload?: unknown
) =>
  requiredObject<T>(
    await tx.$queryRaw<JsonRow[]>`
      SELECT app_rls.c03_record_incident_event(
        ${incidentId},
        ${eventType},
        ${json(eventPayload ?? null)}::jsonb
      ) AS result
    `,
    "record incident event"
  );

export const getIncidentDetailInTransaction = async <T>(tx: IncidentDb, incidentId: string) =>
  requiredObject<T>(
    await tx.$queryRaw<JsonRow[]>`
      SELECT app_rls.c03_get_incident_detail(${incidentId}) AS result
    `,
    "get incident detail"
  );

export const listIncidentsInTransaction = async <T>(
  tx: IncidentDb,
  input: { filters: Record<string, unknown>; limit: number; offset: number }
) =>
  requiredObject<T>(
    await tx.$queryRaw<JsonRow[]>`
      SELECT app_rls.c03_list_incidents(
        ${json(input.filters)}::jsonb,
        ${input.limit}::integer,
        ${input.offset}::integer
      ) AS result
    `,
    "list incidents"
  );

export const patchIncidentInTransaction = async <T>(
  tx: IncidentDb,
  incidentId: string,
  patch: Record<string, unknown>
) =>
  requiredObject<T>(
    await tx.$queryRaw<JsonRow[]>`
      SELECT app_rls.c03_patch_incident(${incidentId}, ${json(patch)}::jsonb) AS result
    `,
    "patch incident"
  );

export const addIncidentEvidenceInTransaction = async <T>(
  tx: IncidentDb,
  incidentId: string,
  evidence: Record<string, unknown>,
  idempotencyKey: string
) =>
  requiredObject<T>(
    await tx.$queryRaw<JsonRow[]>`
      SELECT app_rls.c03_add_incident_evidence(
        ${incidentId},
        ${json(evidence)}::jsonb,
        ${idempotencyKey}
      ) AS result
    `,
    "add incident evidence"
  );

export const loadIncidentEvidenceFileInTransaction = async <T>(
  tx: IncidentDb,
  authority: C03VerifiedDbContext,
  storageKey: string
) =>
  requiredObject<T>(
    await tx.$queryRaw<JsonRow[]>`
      SELECT app_rls.c03_get_incident_evidence_file_by_storage_key(
        ${authority.databaseSessionCapability}, ${authority.purpose}, ${authority.requestId}, ${storageKey}
      ) AS result
    `,
    "load incident evidence file"
  );
