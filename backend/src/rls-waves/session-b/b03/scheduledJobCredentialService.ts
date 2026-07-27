import { createHash, randomBytes, randomUUID } from "crypto";
import { Prisma } from "@prisma/client";

type OperatorDb = Pick<Prisma.TransactionClient, "$queryRaw">;

const requestId = (value: string) => {
  const normalized = String(value || "").trim().toLowerCase();
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(normalized)) {
    throw new Error("Scheduled credential operation requires UUID request ID");
  }
  return normalized;
};

export const generateScheduledJobCapability = () => randomBytes(32).toString("base64url");
export const hashScheduledJobCapability = (rawCapability: string) => {
  if (!/^[A-Za-z0-9_-]{43}$/.test(rawCapability)) throw new Error("Invalid scheduled job capability");
  return createHash("sha256").update(rawCapability, "utf8").digest("hex");
};

export const provisionScheduledJobCredential = async (
  db: OperatorDb,
  input: { scheduleId: string; expiresAt: Date; requestId: string; rotatedFromCredentialId?: string | null }
) => {
  const rawCapability = generateScheduledJobCapability();
  const credentialId = randomUUID();
  await db.$queryRaw(Prisma.sql`
    SELECT app_rls.provision_scheduled_job_credential(
      ${credentialId}, ${input.scheduleId}, ${hashScheduledJobCapability(rawCapability)}, ${input.expiresAt},
      ${input.rotatedFromCredentialId || null}, ${requestId(input.requestId)}
    )
  `);
  return { credentialId, rawCapability };
};

export const revokeScheduledJobCredential = async (
  db: OperatorDb,
  input: { credentialId: string; reason: string; requestId: string }
) => db.$queryRaw(Prisma.sql`
  SELECT app_rls.revoke_scheduled_job_credential(
    ${input.credentialId}, ${String(input.reason || "").trim()}, ${requestId(input.requestId)}
  ) AS revoked
`);
