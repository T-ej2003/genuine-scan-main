import { AlertSeverity, PolicyRuleType, Prisma } from "@prisma/client";

type PolicyDb = Pick<Prisma.TransactionClient, "$queryRaw">;

type JsonRow = { result: Prisma.JsonValue };

const requiredObject = <T>(rows: JsonRow[], operation: string): T => {
  const result = rows[0]?.result;
  if (!result || typeof result !== "object" || Array.isArray(result)) {
    throw new Error(`${operation} returned an invalid database result`);
  }
  return result as T;
};

const json = (value: unknown) => JSON.stringify(value ?? {});

export const listPolicyRulesInTransaction = async <T>(
  tx: PolicyDb,
  input: {
    ruleType?: PolicyRuleType;
    isActive?: boolean;
    limit: number;
    offset: number;
  }
) =>
  requiredObject<T>(
    await tx.$queryRaw<JsonRow[]>`
      SELECT app_rls.c03_list_policy_rules(
        ${input.ruleType || null}::text,
        ${input.isActive ?? null}::boolean,
        ${input.limit}::integer,
        ${input.offset}::integer
      ) AS result
    `,
    "list policy rules"
  );

export const listPlatformPolicyRulesInTransaction = async <T>(
  tx: PolicyDb,
  input: {
    ruleType?: PolicyRuleType;
    isActive?: boolean;
    limit: number;
    offset: number;
  }
) =>
  requiredObject<T>(
    await tx.$queryRaw<JsonRow[]>`
      SELECT app_rls.c03_list_platform_policy_rules(
        ${input.ruleType || null}::text,
        ${input.isActive ?? null}::boolean,
        ${input.limit}::integer,
        ${input.offset}::integer
      ) AS result
    `,
    "list platform policy rules"
  );

export const createPolicyRuleInTransaction = async <T>(
  tx: PolicyDb,
  input: {
    name: string;
    description?: string | null;
    ruleType: PolicyRuleType;
    isActive: boolean;
    threshold: number;
    windowMinutes: number;
    severity: AlertSeverity;
    autoCreateIncident: boolean;
    incidentSeverity?: string | null;
    incidentPriority?: string | null;
    manufacturerId?: string | null;
    actionConfig?: unknown;
  }
) =>
  requiredObject<T>(
    await tx.$queryRaw<JsonRow[]>`
      SELECT app_rls.c03_create_policy_rule(${json(input)}::jsonb) AS result
    `,
    "create policy rule"
  );

export const updatePolicyRuleInTransaction = async <T>(
  tx: PolicyDb,
  ruleId: string,
  patch: Record<string, unknown>
) =>
  requiredObject<T>(
    await tx.$queryRaw<JsonRow[]>`
      SELECT app_rls.c03_update_policy_rule(${ruleId}, ${json(patch)}::jsonb) AS result
    `,
    "update policy rule"
  );

export type C03PolicyAlertRow = {
  id: string;
  licenseeId: string;
  alertType: string;
  severity: string;
  message: string;
  score: number;
  policyRuleId: string | null;
  incidentId: string | null;
  batchId: string | null;
  qrCodeId: string | null;
  manufacturerId: string | null;
  acknowledgedAt: Date | null;
  createdAt: Date;
};

type AlertRow = {
  id: string;
  licenseeId: string;
  alertType: string;
  severity: string;
  message: string;
  score: number;
  policyRuleId: string | null;
  incidentId: string | null;
  batchId: string | null;
  qrCodeId: string | null;
  manufacturerId: string | null;
  acknowledgedAt: Date | null;
  createdAt: Date;
  totalCount: bigint | number;
};

export const listIncidentPolicyAlertsInTransaction = async (
  tx: Pick<Prisma.TransactionClient, "$queryRaw">,
  input: {
    incidentAuthorizationId: string;
    incidentId: string;
    licenseeId: string;
    filters: Record<string, unknown>;
    limit: number;
    offset: number;
  }
) =>
  tx.$queryRaw<AlertRow[]>`
    SELECT id,
           licensee_id AS "licenseeId",
           alert_type AS "alertType",
           severity,
           message,
           score,
           policy_rule_id AS "policyRuleId",
           incident_id AS "incidentId",
           batch_id AS "batchId",
           qr_code_id AS "qrCodeId",
           manufacturer_id AS "manufacturerId",
           acknowledged_at AS "acknowledgedAt",
           created_at AS "createdAt",
           total_count AS "totalCount"
      FROM app_rls.c03_list_ir_alerts(
        ${input.incidentAuthorizationId},
        ${input.incidentId},
        ${input.licenseeId},
        ${json(input.filters)}::jsonb,
        ${input.limit},
        ${input.offset}
      )
  `;

export const linkPolicyAlertToIncidentInTransaction = async <T>(
  tx: Pick<Prisma.TransactionClient, "$queryRaw">,
  input: {
    incidentAuthorizationId: string;
    alertId: string;
    incidentId: string;
    reason: string;
    idempotencyKey: string;
  }
) => {
  const rows = await tx.$queryRaw<JsonRow[]>`
    SELECT to_jsonb(linked) AS result
      FROM app_rls.c03_link_ir_alert_incident(
        ${input.incidentAuthorizationId},
        ${input.alertId},
        ${input.incidentId},
        ${input.reason},
        ${input.idempotencyKey}
      ) AS linked
  `;
  return requiredObject<T>(rows, "link policy alert to incident");
};
