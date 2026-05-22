import { Request } from "express";
import { z } from "zod";

export const agentAuthSchema = z
  .object({
    agentId: z.string().trim().min(3).max(180),
    deviceFingerprint: z.string().trim().min(8).max(256),
    printerId: z.string().trim().min(1).max(180),
    issuedAt: z.string().trim().min(10).max(80),
    nonce: z.string().trim().min(8).max(180),
    signature: z.string().trim().min(16).max(4096),
  })
  .strict();

export const claimSchema = agentAuthSchema
  .extend({
    protocolVersion: z.string().trim().max(80).optional().nullable(),
    buildVersion: z.string().trim().max(80).optional().nullable(),
    selectedPrinterId: z.string().trim().max(180).optional().nullable(),
    selectedPrinterName: z.string().trim().max(180).optional().nullable(),
    deviceName: z.string().trim().max(180).optional(),
    agentVersion: z.string().trim().max(80).optional(),
  })
  .strict();

const localAgentProtocolFields = {
  protocolVersion: z.string().trim().max(80).optional().nullable(),
  buildVersion: z.string().trim().max(80).optional().nullable(),
};

const nullableTrimmedString = (max: number) => z.union([z.string().trim().max(max), z.null()]).optional();
const metadataSchema = z.record(z.any()).optional().nullable();

export const confirmSchema = agentAuthSchema
  .extend({
    ...localAgentProtocolFields,
    printJobId: z.string().trim().uuid(),
    printSessionId: z.string().trim().uuid().optional().nullable(),
    printItemId: z.string().trim().uuid(),
    code: z.string().trim().max(180).optional().nullable(),
    payloadHash: z.string().trim().max(256).optional().or(z.literal("")),
    bytesWritten: z.coerce.number().int().min(1).max(50_000_000).optional(),
    deviceJobRef: nullableTrimmedString(240),
    markDispatched: z.boolean().optional(),
    agentMetadata: metadataSchema,
    dispatchMetadata: metadataSchema,
  })
  .strict();

export const localAgentAckSchema = confirmSchema;

export const failSchema = agentAuthSchema
  .extend({
    ...localAgentProtocolFields,
    printJobId: z.string().trim().uuid(),
    printSessionId: z.string().trim().uuid().optional().nullable(),
    printItemId: z.string().trim().uuid(),
    code: z.string().trim().max(180).optional().nullable(),
    reason: z.string().trim().min(2).max(1000),
    agentMetadata: metadataSchema,
  })
  .strict();

export type LocalAgentRequestPayload =
  | z.infer<typeof agentAuthSchema>
  | z.infer<typeof claimSchema>
  | z.infer<typeof localAgentAckSchema>
  | z.infer<typeof confirmSchema>
  | z.infer<typeof failSchema>;

export const getLocalAgentRequestId = (req: Request) =>
  String((req as Request & { requestId?: string }).requestId || req.get("x-request-id") || "").trim() || null;

const issuePath = (issue: { path: Array<string | number> }) =>
  issue.path.map((part) => String(part)).filter(Boolean).join(".");

export const buildLocalAgentValidationErrorPayload = (params: {
  req?: Request;
  body?: any;
  errorCode: string;
  message: string;
  issues?: Array<z.ZodIssue | { code?: string; path: Array<string | number>; message: string; received?: string }>;
}) => {
  const issues = params.issues || [];
  const validationIssuePaths = issues.map(issuePath).filter(Boolean);
  const missingFields = issues
    .filter((issue) => issue.code === "invalid_type" && (issue as z.ZodInvalidTypeIssue).received === "undefined")
    .map(issuePath)
    .filter(Boolean);
  return {
    success: false,
    error: params.message,
    message: params.message,
    code: params.errorCode,
    errorCode: params.errorCode,
    requestId: params.req ? getLocalAgentRequestId(params.req) : null,
    details: {
      validationIssuePaths,
      missingFields,
      protocolVersion: params.body?.protocolVersion || params.body?.agentMetadata?.protocolVersion || null,
      buildVersion: params.body?.buildVersion || params.body?.agentMetadata?.buildVersion || null,
    },
  };
};

export const validateLocalAgentAckDispatchPhase = (body: z.infer<typeof localAgentAckSchema>) => {
  const markDispatched = body.markDispatched !== false;
  if (!markDispatched) return { ok: true as const };
  const deviceJobRef = String(body.deviceJobRef || "").trim();
  const dispatchMetadata = body.dispatchMetadata && typeof body.dispatchMetadata === "object" ? body.dispatchMetadata : null;
  const agentMetadata = body.agentMetadata && typeof body.agentMetadata === "object" ? body.agentMetadata : null;
  const hasDispatchMetadata = Boolean(
    dispatchMetadata ||
      String(agentMetadata?.printPath || "").trim() ||
      String(agentMetadata?.jobRef || "").trim() ||
      String(agentMetadata?.labelLanguage || "").trim()
  );
  if (deviceJobRef || hasDispatchMetadata) return { ok: true as const };
  return {
    ok: false as const,
    issues: [
      { code: "custom", path: ["deviceJobRef"], message: "Dispatch ACK requires a device job reference or spooler dispatch metadata." },
      { code: "custom", path: ["dispatchMetadata"], message: "Dispatch ACK requires spooler dispatch metadata when markDispatched is true." },
    ],
  };
};
