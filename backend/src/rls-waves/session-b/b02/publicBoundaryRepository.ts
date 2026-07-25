import { createHash, randomBytes } from "crypto";
import { Prisma } from "@prisma/client";

export type B02PublicFunctionClient = Pick<Prisma.TransactionClient, "$queryRaw">;

type VerifyRawQrBoundaryRow = {
  result: string;
  messageKey: string;
  nextAction: string;
  maskedCode: string;
  brandName: string | null;
  brandWebsite: string | null;
  brandSupportEmail: string | null;
  brandSupportPhone: string | null;
  manufacturerName: string | null;
  manufacturerWebsite: string | null;
  printedAt: Date | null;
  firstVerifiedAt: Date | null;
  latestVerifiedAt: Date | null;
  ownershipClaimAvailable: boolean;
  sessionStartToken: string | null;
};

export type VerifyRawQrRow = VerifyRawQrBoundaryRow & { reportSessionAvailable: boolean };
type VerifySignedQrBoundaryRow = VerifyRawQrBoundaryRow & { verificationMethod: string };
export type VerifySignedQrRow = VerifyRawQrRow & { verificationMethod: string };
export class PublicSignedTokenRejectedError extends Error {
  readonly code = "PUBLIC_SIGNED_TOKEN_INVALID";

  constructor() {
    super("Signed QR token could not be verified");
    this.name = "PublicSignedTokenRejectedError";
  }
}
export type RecordQrVerificationRow = { decisionKey: string; recorded: boolean };
export type StartVerificationSessionRow = {
  sessionId: string;
  sessionProofToken: string;
  maskedCode: string;
  customerFacingState: string;
  entryMethod: string;
  authState: string;
  startedAt: Date;
  expiresAt: Date;
  proofBindingExpiresAt: Date;
  brandName: string | null;
};
export type ReadVerificationSessionRow = {
  sessionId: string;
  maskedCode: string;
  customerFacingState: string;
  startedAt: Date;
  expiresAt: Date;
  proofBindingExpiresAt: Date;
  entryMethod: string;
  authState: string;
  intakeCompleted: boolean;
  revealed: boolean;
  brandName: string | null;
  verification: Record<string, unknown> | null;
};
export type TrackSupportStatusRow = {
  referenceCode: string;
  customerFacingStatus: string;
  priority: string;
  updatedAt: Date;
  handoffStage: string | null;
  slaDueAt: Date | null;
};
export type AcceptedRow = { accepted: boolean; publicReference: string; message: string };
type IntakeAcceptedRow = AcceptedRow & { deliveryRequired: boolean };

type FieldType = "string" | "number" | "boolean" | "date" | "json";
type Projection = ReadonlyArray<readonly [string, FieldType, boolean?]>;

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const VERSIONED_DIGEST = /^(?:[A-Za-z0-9._-]{1,32}:)?[a-f0-9]{64}$/;
const CUSTOMER_USER_ID = /^cust_[a-f0-9]{32}$/;
const RAW_QR = /^[A-Za-z0-9][A-Za-z0-9_-]{7,127}$/;
const REFERENCE = /^[A-Z0-9][A-Z0-9_-]{3,63}$/;

const exactInput = (input: object, keys: readonly string[], label: string) => {
  const allowed = new Set(keys);
  const unexpected = Object.keys(input).find((key) => !allowed.has(key));
  if (unexpected) throw new Error(`${label} received unexpected input ${unexpected}`);
};

const text = (value: unknown, label: string, minimum: number, maximum: number) => {
  if (typeof value !== "string") throw new Error(`${label} must be text`);
  const normalized = value.trim();
  if (normalized.length < minimum || normalized.length > maximum) {
    throw new Error(`${label} has invalid length`);
  }
  return normalized;
};

const optionalText = (value: unknown, label: string, maximum: number) => {
  if (value == null || value === "") return null;
  return text(value, label, 1, maximum);
};

const matches = (value: unknown, label: string, pattern: RegExp, maximum = 256) => {
  const normalized = text(value, label, 1, maximum);
  if (!pattern.test(normalized)) throw new Error(`${label} is malformed`);
  return normalized;
};

const optionalMatches = (value: unknown, label: string, pattern: RegExp, maximum = 256) =>
  value == null || value === "" ? null : matches(value, label, pattern, maximum);

const uuid = (value: unknown, label: string) => matches(value, label, UUID, 36).toLowerCase();
const optionalUuid = (value: unknown, label: string) => value == null || value === "" ? null : uuid(value, label);
const digest = (value: unknown, label: string) => matches(value, label, VERSIONED_DIGEST, 97);
const optionalDigest = (value: unknown, label: string) => value == null || value === "" ? null : digest(value, label);
const requestId = (value: unknown) => matches(value, "request ID", /^[\x21-\x7e]{1,128}$/, 128);

const date = (value: unknown, label: string) => {
  if (!(value instanceof Date) || !Number.isFinite(value.getTime())) throw new Error(`${label} is invalid`);
  return value;
};

const integer = (value: unknown, label: string, minimum: number, maximum: number) => {
  if (!Number.isInteger(value) || Number(value) < minimum || Number(value) > maximum) {
    throw new Error(`${label} is invalid`);
  }
  return Number(value);
};

const oneOf = <T extends string>(value: unknown, label: string, allowed: readonly T[]) => {
  const normalized = text(value, label, 1, 64) as T;
  if (!allowed.includes(normalized)) throw new Error(`${label} is unsupported`);
  return normalized;
};

const email = (value: unknown, label: string) => {
  const normalized = text(value, label, 3, 160).toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalized)) throw new Error(`${label} is malformed`);
  return normalized;
};

const optionalEmail = (value: unknown, label: string) => value == null || value === "" ? null : email(value, label);

const url = (value: unknown, label: string, maximum: number) => {
  const normalized = text(value, label, 1, maximum);
  let parsed: URL;
  try {
    parsed = new URL(normalized);
  } catch {
    throw new Error(`${label} is malformed`);
  }
  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") throw new Error(`${label} is unsupported`);
  return parsed.toString();
};

const optionalUrl = (value: unknown, label: string, maximum: number) =>
  value == null || value === "" ? null : url(value, label, maximum);

const rawQr = (value: unknown) => {
  const normalized = text(value, "requested QR code", 8, 128);
  if (!RAW_QR.test(normalized)) throw new Error("requested QR code is malformed");
  return normalized;
};

const customerUserId = (value: unknown) =>
  value == null || value === "" ? null : matches(value, "customer user ID", CUSTOMER_USER_ID, 37);

const exactOne = <T extends Record<string, unknown>>(
  rows: T[],
  functionName: string,
  projection: Projection
): T | null => {
  if (rows.length > 1) throw new Error(`${functionName} returned more than one row`);
  const row = rows[0];
  if (!row) return null;
  const expected = projection.map(([key]) => key).sort();
  const actual = Object.keys(row).sort();
  if (expected.length !== actual.length || actual.some((key, index) => key !== expected[index])) {
    throw new Error(`${functionName} returned an unexpected projection`);
  }
  for (const [key, type, nullable] of projection) {
    const value = row[key];
    if (nullable && value == null) continue;
    const valid = type === "date"
      ? value instanceof Date && Number.isFinite(value.getTime())
      : type === "json"
        ? value !== null && typeof value === "object" && !Array.isArray(value)
      : typeof value === type;
    if (!valid) throw new Error(`${functionName} returned an invalid ${key}`);
  }
  return row;
};

const verifyRawProjection: Projection = [
  ["result", "string"], ["messageKey", "string"], ["nextAction", "string"], ["maskedCode", "string"],
  ["brandName", "string", true], ["brandWebsite", "string", true],
  ["brandSupportEmail", "string", true], ["brandSupportPhone", "string", true],
  ["manufacturerName", "string", true], ["manufacturerWebsite", "string", true],
  ["printedAt", "date", true], ["firstVerifiedAt", "date", true], ["latestVerifiedAt", "date", true],
  ["ownershipClaimAvailable", "boolean"], ["sessionStartToken", "string", true],
];
const acceptedProjection: Projection = [
  ["accepted", "boolean"], ["publicReference", "string"], ["message", "string"],
];
const intakeAcceptedProjection: Projection = [...acceptedProjection, ["deliveryRequired", "boolean"]];
const sessionStartProjection: Projection = [
  ["sessionId", "string"], ["sessionProofToken", "string"], ["maskedCode", "string"],
  ["customerFacingState", "string"], ["entryMethod", "string"], ["authState", "string"],
  ["startedAt", "date"], ["expiresAt", "date"], ["proofBindingExpiresAt", "date"],
  ["brandName", "string", true],
];
const sessionReadProjection: Projection = [
  ["sessionId", "string"], ["maskedCode", "string"], ["customerFacingState", "string"],
  ["startedAt", "date"], ["expiresAt", "date"], ["proofBindingExpiresAt", "date"],
  ["entryMethod", "string"], ["authState", "string"], ["intakeCompleted", "boolean"],
  ["revealed", "boolean"], ["brandName", "string", true], ["verification", "json", true],
];

const stable = (value: unknown): string => {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stable).join(",")}]`;
  return `{${Object.keys(value as Record<string, unknown>)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${stable((value as Record<string, unknown>)[key])}`)
    .join(",")}}`;
};

export const b02IdempotencyDigest = (value: unknown) =>
  createHash("sha256").update(stable(value)).digest("hex");

const proof = () => {
  const raw = randomBytes(32).toString("base64url");
  return { raw, hash: createHash("sha256").update(raw).digest("hex") };
};

const REPORT_SESSION_RESULTS = new Set(["AUTHENTIC", "AUTHENTIC_REPEAT", "REVIEW", "BLOCKED", "NOT_READY"]);
const withSessionPolicy = <T extends VerifyRawQrBoundaryRow>(row: T, rawToken: string) => {
  const reportSessionAvailable = REPORT_SESSION_RESULTS.has(row.result);
  return {
    ...row,
    reportSessionAvailable,
    sessionStartToken: row.ownershipClaimAvailable || reportSessionAvailable ? rawToken : null,
  };
};

export const issueCustomerAuthSession = async (
  db: B02PublicFunctionClient,
  input: {
    capability: string;
    customerUserId: string;
    customerEmail: string;
    authStrength: string;
    authProvider: string;
    issuedAt: Date;
    expiresAt: Date;
    requestId: string;
  }
) => {
  exactInput(input, [
    "capability", "customerUserId", "customerEmail", "authStrength", "authProvider",
    "issuedAt", "expiresAt", "requestId",
  ], "issue_customer_auth_session");
  const rows = await db.$queryRaw<Array<{ accepted: boolean }>>`
    SELECT * FROM app_public.issue_customer_auth_session(
      ${text(input.capability, "customer session capability", 32, 4096)},
      ${matches(input.customerUserId, "customer user ID", CUSTOMER_USER_ID, 37)},
      ${email(input.customerEmail, "customer email")},
      ${oneOf(input.authStrength, "customer authentication strength", ["EMAIL_OTP","PASSKEY","SOCIAL"] as const)},
      ${oneOf(input.authProvider, "customer authentication provider", ["EMAIL_OTP","GOOGLE"] as const)},
      ${date(input.issuedAt, "customer session issue time")},
      ${date(input.expiresAt, "customer session expiry time")},
      ${requestId(input.requestId)}
    )
  `;
  return exactOne(rows, "app_public.issue_customer_auth_session", [["accepted","boolean"]]);
};

export const revokeCustomerAuthSession = async (
  db: B02PublicFunctionClient,
  input: { capability: string; revokedAt: Date; requestId: string }
) => {
  exactInput(input, ["capability","revokedAt","requestId"], "revoke_customer_auth_session");
  return exactOne(await db.$queryRaw<Array<{ revoked: boolean }>>`
    SELECT * FROM app_public.revoke_customer_auth_session(
      ${text(input.capability, "customer session capability", 32, 4096)},
      ${date(input.revokedAt, "customer session revocation time")},
      ${requestId(input.requestId)}
    )
  `, "app_public.revoke_customer_auth_session", [["revoked","boolean"]]);
};

export const readCustomerAuthSession = async (
  db: B02PublicFunctionClient,
  input: { capability: string; checkedAt: Date; requestId: string }
) => {
  exactInput(input, ["capability","checkedAt","requestId"], "read_customer_auth_session");
  return exactOne(await db.$queryRaw<Array<{
    customerUserId: string;
    customerEmail: string;
    authStrength: string;
    authProvider: string;
  }>>`
    SELECT * FROM app_public.read_customer_auth_session(
      ${text(input.capability, "customer session capability", 32, 4096)},
      ${date(input.checkedAt, "customer session check time")},
      ${requestId(input.requestId)}
    )
  `, "app_public.read_customer_auth_session", [
    ["customerUserId","string"],["customerEmail","string"],
    ["authStrength","string"],["authProvider","string"],
  ]);
};

export const verifyRawQr = async (
  db: B02PublicFunctionClient,
  input: {
    requestedCode: string;
    checkedAt: Date;
    requestId: string;
    actorIpHash?: string | null;
    actorDeviceHash?: string | null;
  }
) => {
  exactInput(input, ["requestedCode", "checkedAt", "requestId", "actorIpHash", "actorDeviceHash"], "verify_raw_qr");
  const requestedCode = rawQr(input.requestedCode);
  const checkedAt = date(input.checkedAt, "verification time");
  const validatedRequestId = requestId(input.requestId);
  const actorIpHash = optionalDigest(input.actorIpHash, "actor IP digest");
  const actorDeviceHash = optionalDigest(input.actorDeviceHash, "actor device digest");
  const sessionStart = proof();
  const row = exactOne(await db.$queryRaw<VerifyRawQrBoundaryRow[]>`
    SELECT * FROM app_public.verify_raw_qr(
      ${requestedCode}::text,
      ${checkedAt}::timestamp without time zone,
      ${validatedRequestId}::text,
      ${actorIpHash}::text,
      ${actorDeviceHash}::text,
      ${sessionStart.hash}::text
    )
  `, "app_public.verify_raw_qr", verifyRawProjection);
  return row ? withSessionPolicy(row, sessionStart.raw) : null;
};

export const verifySignedQr = async (
  db: B02PublicFunctionClient,
  input: {
    tokenDigest: string;
    qrId: string;
    licenseeId: string;
    batchId?: string | null;
    manufacturerId?: string | null;
    nonce: string;
    replayEpoch: number;
    keyVersion: string;
    issuedAt: Date;
    expiresAt: Date;
    checkedAt: Date;
    requestId: string;
    actorIpHash?: string | null;
    actorDeviceHash?: string | null;
  }
) => {
  exactInput(input, [
    "tokenDigest", "qrId", "licenseeId", "batchId", "manufacturerId", "nonce", "replayEpoch",
    "keyVersion", "issuedAt", "expiresAt", "checkedAt", "requestId", "actorIpHash", "actorDeviceHash",
  ], "verify_signed_qr");
  const tokenDigest = digest(input.tokenDigest, "signed QR token digest");
  const qrId = uuid(input.qrId, "QR ID");
  const licenseeId = uuid(input.licenseeId, "licensee ID");
  const batchId = optionalUuid(input.batchId, "batch ID");
  const manufacturerId = optionalUuid(input.manufacturerId, "manufacturer ID");
  const nonce = matches(input.nonce, "signed QR nonce", /^[A-Za-z0-9_-]{8,256}$/, 256);
  const replayEpoch = integer(input.replayEpoch, "signed QR replay epoch", 1, 2_147_483_647);
  const keyVersion = matches(input.keyVersion, "signing key version", /^[A-Za-z0-9._-]{1,64}$/, 64);
  const issuedAt = date(input.issuedAt, "signed QR issue time");
  const expiresAt = date(input.expiresAt, "signed QR expiry time");
  const checkedAt = date(input.checkedAt, "verification time");
  if (issuedAt.getTime() > checkedAt.getTime() || checkedAt.getTime() >= expiresAt.getTime()) {
    throw new PublicSignedTokenRejectedError();
  }
  const validatedRequestId = requestId(input.requestId);
  const actorIpHash = optionalDigest(input.actorIpHash, "actor IP digest");
  const actorDeviceHash = optionalDigest(input.actorDeviceHash, "actor device digest");
  const sessionStart = proof();
  const row = exactOne(await db.$queryRaw<VerifySignedQrBoundaryRow[]>`
    SELECT * FROM app_public.verify_signed_qr(
      ${tokenDigest}, ${qrId}, ${licenseeId}, ${batchId}, ${manufacturerId}, ${nonce}, ${replayEpoch},
      ${keyVersion}, ${issuedAt}, ${expiresAt}, ${checkedAt}, ${validatedRequestId}, ${actorIpHash}, ${actorDeviceHash},
      ${sessionStart.hash}
    )
  `, "app_public.verify_signed_qr", [...verifyRawProjection, ["verificationMethod", "string"]]);
  return row ? withSessionPolicy(row, sessionStart.raw) : null;
};

export const recordQrVerification = async (
  db: B02PublicFunctionClient,
  input: {
    qrId: string;
    proofClass: string;
    outcomeCode: string;
    scannedAt: Date;
    requestId: string;
    actorIpHash?: string | null;
    actorDeviceHash?: string | null;
  }
) => {
  exactInput(input, ["qrId", "proofClass", "outcomeCode", "scannedAt", "requestId", "actorIpHash", "actorDeviceHash"], "record_qr_verification");
  const qrId = uuid(input.qrId, "QR ID");
  const proofClass = oneOf(input.proofClass, "verification proof class", ["SIGNED_LABEL", "MANUAL_CODE_LOOKUP", "DEGRADED"] as const);
  const outcomeCode = oneOf(input.outcomeCode, "verification outcome", [
    "AUTHENTIC", "SUSPICIOUS_DUPLICATE", "BLOCKED", "NOT_READY", "NOT_FOUND", "INVALID_SIGNATURE",
    "INVALID_PAYLOAD", "EXPIRED", "TOKEN_MISMATCH", "UNAVAILABLE",
  ] as const);
  const scannedAt = date(input.scannedAt, "scan time");
  const validatedRequestId = requestId(input.requestId);
  const actorIpHash = optionalDigest(input.actorIpHash, "actor IP digest");
  const actorDeviceHash = optionalDigest(input.actorDeviceHash, "actor device digest");
  return exactOne(await db.$queryRaw<RecordQrVerificationRow[]>`
    SELECT * FROM app_public.record_qr_verification(
      ${qrId}, ${proofClass}, ${outcomeCode}, ${scannedAt}, ${validatedRequestId}, ${actorIpHash}, ${actorDeviceHash}
    )
  `, "app_public.record_qr_verification", [["decisionKey", "string"], ["recorded", "boolean"]]);
};

export const startVerificationSession = async (
  db: B02PublicFunctionClient,
  input: {
    sessionStartTokenHash: string;
    entryMethod: string;
    customerCapability?: string | null;
    checkedAt: Date;
    requestId: string;
  }
) => {
  exactInput(input, ["sessionStartTokenHash", "entryMethod", "customerCapability", "checkedAt", "requestId"], "start_verification_session");
  const sessionStartTokenHash = digest(input.sessionStartTokenHash, "session-start token digest");
  const entryMethod = oneOf(input.entryMethod, "verification entry method", ["SIGNED_SCAN", "MANUAL_CODE"] as const);
  const checkedAt = date(input.checkedAt, "session start time");
  const validatedRequestId = requestId(input.requestId);
  const customerCapability = optionalText(input.customerCapability, "customer session capability", 4096);
  const sessionProof = proof();
  const row = exactOne(await db.$queryRaw<StartVerificationSessionRow[]>`
    SELECT * FROM app_public.start_verification_session(
      ${sessionStartTokenHash}, ${entryMethod}, ${customerCapability}, ${checkedAt}, ${validatedRequestId},
      ${sessionProof.hash}
    )
  `, "app_public.start_verification_session", sessionStartProjection);
  return row ? { ...row, sessionProofToken: sessionProof.raw } : null;
};

export const readVerificationSession = async (
  db: B02PublicFunctionClient,
  input: {
    sessionId: string;
    sessionProofHash: string;
    customerCapability?: string | null;
    checkedAt: Date;
    requestId: string;
  }
) => {
  exactInput(input, ["sessionId", "sessionProofHash", "customerCapability", "checkedAt", "requestId"], "read_verification_session");
  const sessionId = uuid(input.sessionId, "verification session ID");
  const sessionProofHash = digest(input.sessionProofHash, "verification-session proof digest");
  const checkedAt = date(input.checkedAt, "session read time");
  const validatedRequestId = requestId(input.requestId);
  const customerCapability = optionalText(input.customerCapability, "customer session capability", 4096);
  return exactOne(await db.$queryRaw<ReadVerificationSessionRow[]>`
    SELECT * FROM app_public.read_verification_session(
      ${sessionId}, ${sessionProofHash}, ${customerCapability}, ${checkedAt}, ${validatedRequestId}
    )
  `, "app_public.read_verification_session", sessionReadProjection);
};

export const writeVerificationSession = async (
  db: B02PublicFunctionClient,
  input: {
    sessionId: string;
    sessionProofHash: string;
    customerCapability: string;
    operation: "INTAKE" | "REVEAL";
    payload: Record<string, unknown>;
    checkedAt: Date;
    requestId: string;
  }
) => {
  exactInput(input, [
    "sessionId", "sessionProofHash", "customerCapability",
    "operation", "payload", "checkedAt", "requestId",
  ], "write_verification_session");
  const rows = await db.$queryRaw<Array<{ result: unknown }>>`
    SELECT app_public.write_verification_session(
      ${uuid(input.sessionId, "verification session ID")},
      ${digest(input.sessionProofHash, "verification-session proof digest")},
      ${text(input.customerCapability, "customer session capability", 32, 4096)},
      ${input.operation},
      ${input.payload}::jsonb,
      ${date(input.checkedAt, "verification session write time")},
      ${requestId(input.requestId)}
    ) AS result
  `;
  if (rows.length !== 1 || !rows[0]?.result || typeof rows[0].result !== "object") {
    throw new Error("app_public.write_verification_session returned an unexpected projection");
  }
  return rows[0].result as Record<string, unknown>;
};

const jsonResult = async (
  rows: Array<{ result: unknown }>,
  name: string
) => {
  if (rows.length !== 1 || !rows[0]?.result || typeof rows[0].result !== "object" || Array.isArray(rows[0].result)) {
    throw new Error(`${name} returned an unexpected projection`);
  }
  return rows[0].result as Record<string, unknown>;
};

export const claimCustomerOwnership = async (
  db: B02PublicFunctionClient,
  input: {
    customerCapability?: string | null;
    sessionId: string;
    sessionProofHash: string;
    deviceTokenHash?: string | null;
    ipHash?: string | null;
    userAgentHash?: string | null;
    linkOnly: boolean;
    checkedAt: Date;
    requestId: string;
  }
) => {
  exactInput(input, [
    "customerCapability","sessionId","sessionProofHash","deviceTokenHash",
    "ipHash","userAgentHash","linkOnly","checkedAt","requestId",
  ], "claim_customer_ownership");
  if (typeof input.linkOnly !== "boolean") throw new Error("claim_customer_ownership requires linkOnly");
  return jsonResult(await db.$queryRaw<Array<{ result: unknown }>>`
    SELECT app_public.claim_customer_ownership(
      ${optionalText(input.customerCapability, "customer session capability", 4096)},
      ${uuid(input.sessionId, "verification session ID")},
      ${digest(input.sessionProofHash, "verification session proof digest")},
      ${optionalDigest(input.deviceTokenHash, "device claim digest")},
      ${optionalDigest(input.ipHash, "claim IP digest")},
      ${optionalDigest(input.userAgentHash, "claim user-agent digest")},
      ${input.linkOnly},
      ${date(input.checkedAt, "ownership claim time")},
      ${requestId(input.requestId)}
    ) AS result
  `, "app_public.claim_customer_ownership");
};

export const createCustomerOwnershipTransfer = async (
  db: B02PublicFunctionClient,
  input: {
    customerCapability: string;
    requestedCode: string;
    recipientEmail?: string | null;
    tokenHash: string;
    expiresAt: Date;
    checkedAt: Date;
    requestId: string;
  }
) => {
  exactInput(input, [
    "customerCapability","requestedCode","recipientEmail","tokenHash","expiresAt","checkedAt","requestId",
  ], "create_customer_ownership_transfer");
  return jsonResult(await db.$queryRaw<Array<{ result: unknown }>>`
    SELECT app_public.create_customer_ownership_transfer(
      ${text(input.customerCapability, "customer session capability", 32, 4096)},
      ${rawQr(input.requestedCode)},
      ${optionalEmail(input.recipientEmail, "ownership transfer recipient")},
      ${digest(input.tokenHash, "ownership transfer token digest")},
      ${date(input.expiresAt, "ownership transfer expiry")},
      ${date(input.checkedAt, "ownership transfer creation time")},
      ${requestId(input.requestId)}
    ) AS result
  `, "app_public.create_customer_ownership_transfer");
};

export const cancelCustomerOwnershipTransfer = async (
  db: B02PublicFunctionClient,
  input: {
    customerCapability: string;
    requestedCode: string;
    transferId?: string | null;
    checkedAt: Date;
    requestId: string;
  }
) => {
  exactInput(input, ["customerCapability","requestedCode","transferId","checkedAt","requestId"], "cancel_customer_ownership_transfer");
  return jsonResult(await db.$queryRaw<Array<{ result: unknown }>>`
    SELECT app_public.cancel_customer_ownership_transfer(
      ${text(input.customerCapability, "customer session capability", 32, 4096)},
      ${rawQr(input.requestedCode)},
      ${optionalUuid(input.transferId, "ownership transfer ID")},
      ${date(input.checkedAt, "ownership transfer cancellation time")},
      ${requestId(input.requestId)}
    ) AS result
  `, "app_public.cancel_customer_ownership_transfer");
};

export const acceptCustomerOwnershipTransfer = async (
  db: B02PublicFunctionClient,
  input: {
    customerCapability: string;
    tokenHash: string;
    ipHash?: string | null;
    userAgentHash?: string | null;
    checkedAt: Date;
    requestId: string;
  }
) => {
  exactInput(input, [
    "customerCapability","tokenHash","ipHash","userAgentHash","checkedAt","requestId",
  ], "accept_customer_ownership_transfer");
  return jsonResult(await db.$queryRaw<Array<{ result: unknown }>>`
    SELECT app_public.accept_customer_ownership_transfer(
      ${text(input.customerCapability, "customer session capability", 32, 4096)},
      ${digest(input.tokenHash, "ownership transfer token digest")},
      ${optionalDigest(input.ipHash, "ownership transfer IP digest")},
      ${optionalDigest(input.userAgentHash, "ownership transfer user-agent digest")},
      ${date(input.checkedAt, "ownership transfer acceptance time")},
      ${requestId(input.requestId)}
    ) AS result
  `, "app_public.accept_customer_ownership_transfer");
};

export const beginCustomerPasskey = async (
  db: B02PublicFunctionClient,
  input: {
    customerCapability?: string | null; customerUserId: string; customerEmail: string;
    purpose: "ENROLLMENT" | "LOGIN" | "STEP_UP"; ticketHash: string; challengeHash: string;
    ipHash?: string | null; userAgentHash?: string | null; origin?: string | null; rpId?: string | null;
    expiresAt: Date; checkedAt: Date; requestId: string;
  }
) => {
  exactInput(input, ["customerCapability","customerUserId","customerEmail","purpose","ticketHash","challengeHash","ipHash","userAgentHash","origin","rpId","expiresAt","checkedAt","requestId"], "begin_customer_passkey");
  return jsonResult(await db.$queryRaw<Array<{ result: unknown }>>`
    SELECT app_public.begin_customer_passkey(
      ${optionalText(input.customerCapability,"customer session capability",4096)},
      ${matches(input.customerUserId,"customer user ID",CUSTOMER_USER_ID,37)},
      ${email(input.customerEmail,"customer email")},
      ${oneOf(input.purpose,"passkey purpose",["ENROLLMENT","LOGIN","STEP_UP"] as const)},
      ${digest(input.ticketHash,"passkey ticket digest")},
      ${digest(input.challengeHash,"passkey challenge digest")},
      ${optionalDigest(input.ipHash,"passkey IP digest")},
      ${optionalDigest(input.userAgentHash,"passkey user-agent digest")},
      ${optionalText(input.origin,"passkey origin",512)},
      ${optionalText(input.rpId,"passkey relying-party ID",253)},
      ${date(input.expiresAt,"passkey expiry")},
      ${date(input.checkedAt,"passkey start time")},
      ${requestId(input.requestId)}
    ) AS result
  `, "app_public.begin_customer_passkey");
};

export const loadCustomerPasskey = async (
  db: B02PublicFunctionClient,
  input: { ticketHashCandidates: string[]; purpose?: "ENROLLMENT" | "LOGIN" | "STEP_UP" | null; credentialId?: string | null; checkedAt: Date; requestId: string }
) => {
  exactInput(input, ["ticketHashCandidates","purpose","credentialId","checkedAt","requestId"], "load_customer_passkey");
  if (!Array.isArray(input.ticketHashCandidates) || input.ticketHashCandidates.length < 1 || input.ticketHashCandidates.length > 4) {
    throw new Error("passkey ticket digest candidates are invalid");
  }
  const hashes = input.ticketHashCandidates.map((value) => digest(value,"passkey ticket digest"));
  return jsonResult(await db.$queryRaw<Array<{ result: unknown }>>`
    SELECT app_public.load_customer_passkey(
      ${hashes}::text[],
      ${input.purpose ? oneOf(input.purpose,"passkey purpose",["ENROLLMENT","LOGIN","STEP_UP"] as const) : null},
      ${optionalText(input.credentialId,"passkey credential ID",1024)},
      ${date(input.checkedAt,"passkey load time")},
      ${requestId(input.requestId)}
    ) AS result
  `, "app_public.load_customer_passkey");
};

export const finishCustomerPasskey = async (
  db: B02PublicFunctionClient,
  input: {
    customerCapability?: string | null; ticketHashCandidates: string[];
    purpose: "ENROLLMENT" | "LOGIN" | "STEP_UP"; payload: Record<string, unknown>;
    checkedAt: Date; requestId: string;
  }
) => {
  exactInput(input, ["customerCapability","ticketHashCandidates","purpose","payload","checkedAt","requestId"], "finish_customer_passkey");
  if (!Array.isArray(input.ticketHashCandidates) || input.ticketHashCandidates.length < 1 || input.ticketHashCandidates.length > 4) {
    throw new Error("passkey ticket digest candidates are invalid");
  }
  const hashes = input.ticketHashCandidates.map((value) => digest(value,"passkey ticket digest"));
  return jsonResult(await db.$queryRaw<Array<{ result: unknown }>>`
    SELECT app_public.finish_customer_passkey(
      ${optionalText(input.customerCapability,"customer session capability",4096)},
      ${hashes}::text[],
      ${oneOf(input.purpose,"passkey purpose",["ENROLLMENT","LOGIN","STEP_UP"] as const)},
      ${input.payload}::jsonb,
      ${date(input.checkedAt,"passkey finish time")},
      ${requestId(input.requestId)}
    ) AS result
  `, "app_public.finish_customer_passkey");
};

export const listCustomerPasskeys = async (
  db: B02PublicFunctionClient,
  input: { customerCapability: string; checkedAt: Date; requestId: string }
) => {
  exactInput(input, ["customerCapability","checkedAt","requestId"], "list_customer_passkeys");
  const rows = await db.$queryRaw<Array<{ payload: Record<string, unknown> }>>`
    SELECT * FROM app_public.list_customer_passkeys(
      ${text(input.customerCapability,"customer session capability",32,4096)},
      ${date(input.checkedAt,"passkey list time")},
      ${requestId(input.requestId)}
    )
  `;
  return rows.map((row) => row.payload);
};

export const deleteCustomerPasskey = async (
  db: B02PublicFunctionClient,
  input: { customerCapability: string; credentialRowId: string; checkedAt: Date; requestId: string }
) => {
  exactInput(input, ["customerCapability","credentialRowId","checkedAt","requestId"], "delete_customer_passkey");
  return exactOne(await db.$queryRaw<Array<{ deleted: boolean }>>`
    SELECT * FROM app_public.delete_customer_passkey(
      ${text(input.customerCapability,"customer session capability",32,4096)},
      ${uuid(input.credentialRowId,"passkey credential row ID")},
      ${date(input.checkedAt,"passkey deletion time")},
      ${requestId(input.requestId)}
    )
  `, "app_public.delete_customer_passkey", [["deleted","boolean"]]);
};

export const trackSupportStatus = async (
  db: B02PublicFunctionClient,
  input: {
    referenceCode: string;
    proofDigest: string;
    proofVersion: number;
    checkedAt: Date;
    requestId: string;
  }
) => {
  exactInput(input, ["referenceCode", "proofDigest", "proofVersion", "checkedAt", "requestId"], "track_support_status");
  const referenceCode = matches(input.referenceCode, "support reference", REFERENCE, 64).toUpperCase();
  const proofDigest = digest(input.proofDigest, "support-status proof digest");
  const proofVersion = integer(input.proofVersion, "support-status proof version", 1, 2_147_483_647);
  const checkedAt = date(input.checkedAt, "support-status check time");
  const validatedRequestId = requestId(input.requestId);
  return exactOne(await db.$queryRaw<TrackSupportStatusRow[]>`
    SELECT * FROM app_public.track_support_status(
      ${referenceCode}, ${proofDigest}, ${proofVersion}, ${checkedAt}, ${validatedRequestId}
    )
  `, "app_public.track_support_status", [
    ["referenceCode", "string"], ["customerFacingStatus", "string"], ["priority", "string"],
    ["updatedAt", "date"], ["handoffStage", "string", true], ["slaDueAt", "date", true],
  ]);
};

export const submitProductFeedback = async (
  db: B02PublicFunctionClient,
  input: {
    requestedCode: string;
    rating: number;
    satisfaction: string;
    notes?: string | null;
    observedStatus?: string | null;
    observedOutcome?: string | null;
    pageUrl?: string | null;
    submittedAt: Date;
    requestId: string;
    actorIpHash?: string | null;
    idempotencyDigest: string;
  }
) => {
  exactInput(input, [
    "requestedCode", "rating", "satisfaction", "notes", "observedStatus", "observedOutcome",
    "pageUrl", "submittedAt", "requestId", "actorIpHash", "idempotencyDigest",
  ], "submit_product_feedback");
  const requestedCode = rawQr(input.requestedCode);
  const rating = integer(input.rating, "feedback rating", 1, 5);
  const satisfaction = oneOf(input.satisfaction, "feedback satisfaction", [
    "very_satisfied", "satisfied", "neutral", "disappointed", "very_disappointed",
  ] as const);
  const notes = optionalText(input.notes, "feedback notes", 1_000);
  const observedStatus = optionalText(input.observedStatus, "observed status", 64);
  const observedOutcome = optionalText(input.observedOutcome, "observed outcome", 64);
  const pageUrl = optionalUrl(input.pageUrl, "feedback page URL", 1_000);
  const submittedAt = date(input.submittedAt, "feedback submission time");
  const validatedRequestId = requestId(input.requestId);
  const actorIpHash = optionalDigest(input.actorIpHash, "actor IP digest");
  const idempotencyDigest = digest(input.idempotencyDigest, "feedback idempotency digest");
  return exactOne(await db.$queryRaw<AcceptedRow[]>`
    SELECT * FROM app_public.submit_product_feedback(
      ${requestedCode}, ${rating}, ${satisfaction}, ${notes}, ${observedStatus}, ${observedOutcome},
      ${pageUrl}, ${submittedAt}, ${validatedRequestId}, ${actorIpHash}, ${idempotencyDigest}
    )
  `, "app_public.submit_product_feedback", acceptedProjection);
};

export const submitPublicIncident = async (
  db: B02PublicFunctionClient,
  input: {
    sessionId: string;
    sessionProofHash: string;
    incidentType: string;
    description: string;
    contactEmail?: string | null;
    consentToContact: boolean;
    evidence?: Array<{ fileUrl: string; storageKey: string; fileType: string }>;
    submittedAt: Date;
    requestId: string;
    actorIpHash?: string | null;
    actorDeviceHash?: string | null;
    idempotencyDigest: string;
  }
) => {
  exactInput(input, [
    "sessionId", "sessionProofHash", "incidentType", "description", "contactEmail", "consentToContact", "evidence", "submittedAt",
    "requestId", "actorIpHash", "actorDeviceHash", "idempotencyDigest",
  ], "submit_public_incident");
  const sessionId = uuid(input.sessionId, "verification session ID");
  const sessionProofHash = digest(input.sessionProofHash, "verification session proof digest");
  const evidence = input.evidence || [];
  if (evidence.length > 4) throw new Error("public incident evidence exceeds the supported limit");
  const incidentType = oneOf(input.incidentType, "public incident type", [
    "counterfeit_suspected", "duplicate_scan", "tampered_label", "wrong_product", "other",
  ] as const);
  const description = text(input.description, "public incident description", 3, 2_000);
  const contactEmail = optionalEmail(input.contactEmail, "public incident contact email");
  if (typeof input.consentToContact !== "boolean") throw new Error("public incident consent must be boolean");
  if (input.consentToContact && !contactEmail) throw new Error("public incident contact consent requires an email");
  const submittedAt = date(input.submittedAt, "public incident submission time");
  const validatedRequestId = requestId(input.requestId);
  const actorIpHash = optionalDigest(input.actorIpHash, "actor IP digest");
  const actorDeviceHash = optionalDigest(input.actorDeviceHash, "actor device digest");
  const idempotencyDigest = digest(input.idempotencyDigest, "public incident idempotency digest");
  return exactOne(await db.$queryRaw<AcceptedRow[]>`
    SELECT * FROM app_public.submit_public_incident(
      ${sessionId}, ${sessionProofHash}, ${incidentType}, ${description}, ${contactEmail}, ${input.consentToContact},
      ${evidence}::jsonb,
      ${submittedAt}, ${validatedRequestId}, ${actorIpHash}, ${actorDeviceHash}, ${idempotencyDigest}
    )
  `, "app_public.submit_public_incident", acceptedProjection);
};

export const submitRequestAccess = async (
  db: B02PublicFunctionClient,
  input: {
    fullName: string;
    workEmail: string;
    companyName: string;
    roleTitle: string;
    country: string;
    monthlyVolume: string;
    message: string;
    sourcePage?: string | null;
    referrer?: string | null;
    submittedAt: Date;
    requestId: string;
    idempotencyDigest: string;
  }
) => {
  exactInput(input, [
    "fullName", "workEmail", "companyName", "roleTitle", "country", "monthlyVolume", "message",
    "sourcePage", "referrer", "submittedAt", "requestId", "idempotencyDigest",
  ], "submit_request_access");
  const fullName = text(input.fullName, "request-access name", 2, 120);
  const workEmail = email(input.workEmail, "request-access email");
  const companyName = text(input.companyName, "request-access company", 2, 160);
  const roleTitle = text(input.roleTitle, "request-access role title", 2, 120);
  const country = text(input.country, "request-access country", 2, 120);
  const monthlyVolume = text(input.monthlyVolume, "request-access monthly volume", 1, 80);
  const message = text(input.message, "request-access message", 10, 3_000);
  const sourcePage = optionalText(input.sourcePage, "request-access source page", 500);
  const referrer = optionalUrl(input.referrer, "request-access referrer", 1_200);
  const submittedAt = date(input.submittedAt, "request-access submission time");
  const validatedRequestId = requestId(input.requestId);
  const idempotencyDigest = digest(input.idempotencyDigest, "request-access idempotency digest");
  return exactOne(await db.$queryRaw<IntakeAcceptedRow[]>`
    SELECT * FROM app_public.submit_request_access(
      ${fullName}, ${workEmail}, ${companyName}, ${roleTitle}, ${country}, ${monthlyVolume}, ${message},
      ${sourcePage}, ${referrer}, ${submittedAt}, ${validatedRequestId}, ${idempotencyDigest}
    )
  `, "app_public.submit_request_access", intakeAcceptedProjection);
};

export const submitPublicSupport = async (
  db: B02PublicFunctionClient,
  input: {
    publicName: string;
    publicEmail: string;
    issueType: string;
    title: string;
    description: string;
    verifiedCode?: string | null;
    productReference?: string | null;
    sourcePath?: string | null;
    pageUrl?: string | null;
    submittedAt: Date;
    requestId: string;
    idempotencyDigest: string;
  }
) => {
  exactInput(input, [
    "publicName", "publicEmail", "issueType", "title", "description", "verifiedCode",
    "productReference", "sourcePath", "pageUrl", "submittedAt", "requestId", "idempotencyDigest",
  ], "submit_public_support");
  const publicName = text(input.publicName, "public support name", 2, 120);
  const publicEmail = email(input.publicEmail, "public support email");
  const issueType = oneOf(input.issueType, "public support issue type", [
    "verification_result", "scan_problem", "product_concern", "platform_access", "privacy", "other",
  ] as const);
  const title = text(input.title, "public support title", 5, 160);
  const description = text(input.description, "public support description", 10, 4_000);
  const verifiedCode = input.verifiedCode == null || input.verifiedCode === "" ? null : rawQr(input.verifiedCode);
  const productReference = optionalText(input.productReference, "public support product reference", 160);
  const sourcePath = optionalText(input.sourcePath, "public support source path", 500);
  if (sourcePath && (!sourcePath.startsWith("/") || sourcePath.includes(".."))) {
    throw new Error("public support source path is malformed");
  }
  const pageUrl = optionalUrl(input.pageUrl, "public support page URL", 1_200);
  const submittedAt = date(input.submittedAt, "public support submission time");
  const validatedRequestId = requestId(input.requestId);
  const idempotencyDigest = digest(input.idempotencyDigest, "public support idempotency digest");
  return exactOne(await db.$queryRaw<IntakeAcceptedRow[]>`
    SELECT * FROM app_public.submit_public_support(
      ${publicName}, ${publicEmail}, ${issueType}, ${title}, ${description}, ${verifiedCode},
      ${productReference}, ${sourcePath}, ${pageUrl}, ${submittedAt}, ${validatedRequestId}, ${idempotencyDigest}
    )
  `, "app_public.submit_public_support", intakeAcceptedProjection);
};

type PublicDeliveryCompletion = {
  idempotencyDigest: string;
  adminStatus: string;
  adminError?: string | null;
  acknowledgementStatus: string;
  acknowledgementError?: string | null;
  completedAt: Date;
  requestId: string;
};

const deliveryStatus = (value: unknown, label: string) =>
  oneOf(value, label, ["SENT","DRY_RUN","DISABLED","FAILED","SKIPPED"] as const);

const completePublicDelivery = async (
  db: B02PublicFunctionClient,
  functionName: "complete_request_access_delivery" | "complete_public_support_delivery",
  input: PublicDeliveryCompletion,
) => {
  exactInput(input, [
    "idempotencyDigest", "adminStatus", "adminError", "acknowledgementStatus",
    "acknowledgementError", "completedAt", "requestId",
  ], functionName);
  const args = [
    digest(input.idempotencyDigest, "public intake idempotency digest"),
    deliveryStatus(input.adminStatus, "admin delivery status"),
    optionalText(input.adminError, "admin delivery error", 80),
    deliveryStatus(input.acknowledgementStatus, "acknowledgement delivery status"),
    optionalText(input.acknowledgementError, "acknowledgement delivery error", 80),
    date(input.completedAt, "delivery completion time"),
    requestId(input.requestId),
  ] as const;
  const rows = functionName === "complete_request_access_delivery"
    ? await db.$queryRaw<Array<{ updated: boolean }>>`
        SELECT * FROM app_public.complete_request_access_delivery(
          ${args[0]},${args[1]},${args[2]},${args[3]},${args[4]},${args[5]},${args[6]}
        )
      `
    : await db.$queryRaw<Array<{ updated: boolean }>>`
        SELECT * FROM app_public.complete_public_support_delivery(
          ${args[0]},${args[1]},${args[2]},${args[3]},${args[4]},${args[5]},${args[6]}
        )
      `;
  return exactOne(rows, `app_public.${functionName}`, [["updated","boolean"]]);
};

export const completeRequestAccessDelivery = (
  db: B02PublicFunctionClient,
  input: PublicDeliveryCompletion,
) => completePublicDelivery(db, "complete_request_access_delivery", input);

export const completePublicSupportDelivery = (
  db: B02PublicFunctionClient,
  input: PublicDeliveryCompletion,
) => completePublicDelivery(db, "complete_public_support_delivery", input);
