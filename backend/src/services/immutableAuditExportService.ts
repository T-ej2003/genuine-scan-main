import { createHash, createHmac, createPrivateKey, sign as cryptoSign } from "crypto";
import JSZip from "jszip";
import prisma from "../config/database";
import { getQrSigningHmacSecret } from "../utils/secretConfig";

const toBase64Url = (buf: Buffer) =>
  buf
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");

const stableStringify = (obj: any): string => {
  if (obj === null || typeof obj !== "object") return JSON.stringify(obj);
  if (Array.isArray(obj)) return `[${obj.map((v) => stableStringify(v)).join(",")}]`;
  const keys = Object.keys(obj).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${stableStringify(obj[k])}`).join(",")}}`;
};

const sha256Hex = (v: Buffer | string) => createHash("sha256").update(v).digest("hex");

const normalizePem = (value: string) => value.replace(/\\n/g, "\n").trim();

type SignatureResult = {
  algorithm: "ed25519" | "hmac-sha256";
  signature: string;
};

const signIntegrityPayload = (payload: string): SignatureResult => {
  const payloadHash = createHash("sha256").update(payload).digest();

  const privateKeyPem = process.env.QR_SIGN_PRIVATE_KEY;
  if (privateKeyPem) {
    const key = createPrivateKey(normalizePem(privateKeyPem));
    const signature = cryptoSign(null, payloadHash, key);
    return { algorithm: "ed25519", signature: toBase64Url(signature) };
  }

  const signature = createHmac("sha256", getQrSigningHmacSecret())
    .update(payloadHash)
    .digest();
  return { algorithm: "hmac-sha256", signature: toBase64Url(signature) };
};

const escapeCsv = (v: any) => {
  const s = v == null ? "" : String(v);
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
};

export const buildImmutableBatchAuditPackage = async (batchId: string) => {
  const batch = await prisma.batch.findUnique({
    where: { id: batchId },
    include: {
      licensee: { select: { id: true, name: true, prefix: true } },
      manufacturer: { select: { id: true, name: true, email: true } },
    },
  });

  if (!batch) {
    throw new Error("Batch not found");
  }

  const [qrCodes, traceEvents, policyAlerts] = await Promise.all([
    prisma.qRCode.findMany({
      where: { batchId },
      orderBy: [{ code: "asc" }],
      select: {
        id: true,
        code: true,
        status: true,
        scanCount: true,
        printedAt: true,
        redeemedAt: true,
        blockedAt: true,
        tokenHash: true,
        tokenIssuedAt: true,
        tokenExpiresAt: true,
        createdAt: true,
        updatedAt: true,
      },
    }),
    prisma.traceEvent.findMany({
      where: { batchId },
      orderBy: [{ createdAt: "asc" }, { id: "asc" }],
      include: {
        user: { select: { id: true, name: true, email: true } },
        manufacturer: { select: { id: true, name: true, email: true } },
        qrCode: { select: { id: true, code: true } },
      },
    }),
    prisma.policyAlert.findMany({
      where: { batchId },
      orderBy: [{ createdAt: "asc" }, { id: "asc" }],
      include: {
        acknowledgedByUser: { select: { id: true, name: true, email: true } },
      },
    }),
  ]);

  const generatedAt = new Date().toISOString();

  const statusCounts = qrCodes.reduce((acc, qr) => {
    acc[qr.status] = (acc[qr.status] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);

  let prevHash = sha256Hex("GENESIS");
  const chainRecords = traceEvents.map((event, index) => {
    const payload = {
      index: index + 1,
      eventId: event.id,
      eventType: event.eventType,
      createdAt: event.createdAt.toISOString(),
      sourceAction: event.sourceAction || null,
      batchId: event.batchId || null,
      qrCodeId: event.qrCodeId || null,
      qrCode: event.qrCode ? { id: event.qrCode.id, code: event.qrCode.code } : null,
      manufacturer: event.manufacturer
        ? { id: event.manufacturer.id, name: event.manufacturer.name, email: event.manufacturer.email }
        : null,
      actor: event.user ? { id: event.user.id, name: event.user.name, email: event.user.email } : null,
      details: event.details ?? null,
    };

    const eventHash = sha256Hex(`${prevHash}|${stableStringify(payload)}`);
    const record = {
      ...payload,
      prevHash,
      eventHash,
    };
    prevHash = eventHash;
    return record;
  });

  const chainRoot = chainRecords.length ? chainRecords[chainRecords.length - 1].eventHash : sha256Hex("EMPTY_CHAIN");

  const batchManifestJson = {
    generatedAt,
    batch: {
      id: batch.id,
      name: batch.name,
      licenseeId: batch.licenseeId,
      licensee: batch.licensee,
      manufacturer: batch.manufacturer,
      startCode: batch.startCode,
      endCode: batch.endCode,
      totalCodes: batch.totalCodes,
      printedAt: batch.printedAt?.toISOString() || null,
      createdAt: batch.createdAt.toISOString(),
      updatedAt: batch.updatedAt.toISOString(),
    },
    qrSummary: {
      total: qrCodes.length,
      statusCounts,
    },
  };

  const qrManifestCsv = [
    "qrCodeId,code,status,scanCount,printedAt,redeemedAt,blockedAt,tokenHash,tokenIssuedAt,tokenExpiresAt",
    ...qrCodes.map((qr) =>
      [
        escapeCsv(qr.id),
        escapeCsv(qr.code),
        escapeCsv(qr.status),
        escapeCsv(qr.scanCount),
        escapeCsv(qr.printedAt?.toISOString() || ""),
        escapeCsv(qr.redeemedAt?.toISOString() || ""),
        escapeCsv(qr.blockedAt?.toISOString() || ""),
        escapeCsv(qr.tokenHash || ""),
        escapeCsv(qr.tokenIssuedAt?.toISOString() || ""),
        escapeCsv(qr.tokenExpiresAt?.toISOString() || ""),
      ].join(",")
    ),
  ].join("\n");

  const traceEventsJson = JSON.stringify(
    traceEvents.map((e) => ({
      id: e.id,
      eventType: e.eventType,
      createdAt: e.createdAt.toISOString(),
      sourceAction: e.sourceAction,
      batchId: e.batchId,
      qrCodeId: e.qrCodeId,
      manufacturerId: e.manufacturerId,
      userId: e.userId,
      details: e.details,
    })),
    null,
    2
  );

  const eventChainJsonl = chainRecords.map((r) => JSON.stringify(r)).join("\n");

  const policyAlertsJson = JSON.stringify(
    policyAlerts.map((a) => ({
      id: a.id,
      alertType: a.alertType,
      severity: a.severity,
      score: a.score,
      message: a.message,
      createdAt: a.createdAt.toISOString(),
      acknowledgedAt: a.acknowledgedAt?.toISOString() || null,
      acknowledgedByUser: a.acknowledgedByUser
        ? {
            id: a.acknowledgedByUser.id,
            name: a.acknowledgedByUser.name,
            email: a.acknowledgedByUser.email,
          }
        : null,
      details: a.details ?? null,
    })),
    null,
    2
  );

  const files: Record<string, string> = {
    "batch-manifest.json": JSON.stringify(batchManifestJson, null, 2),
    "batch-manifest.csv": qrManifestCsv,
    "trace-events.json": traceEventsJson,
    "event-chain.jsonl": eventChainJsonl,
    "policy-alerts.json": policyAlertsJson,
  };

  const fileHashes = Object.entries(files).reduce((acc, [name, content]) => {
    acc[name] = sha256Hex(content);
    return acc;
  }, {} as Record<string, string>);

  const integrityPayload = {
    generatedAt,
    batchId: batch.id,
    chainRoot,
    eventCount: chainRecords.length,
    fileHashes,
  };
  const integrityCanonical = stableStringify(integrityPayload);
  const integrityHash = sha256Hex(integrityCanonical);
  const signature = signIntegrityPayload(integrityCanonical);

  files["integrity.json"] = JSON.stringify(
    {
      ...integrityPayload,
      integrityHash,
      signature,
      verification: {
        note:
          "Recompute SHA-256 for each file and compare with fileHashes, then verify integrityHash and signature.",
      },
    },
    null,
    2
  );

  files["README.txt"] = [
    "Immutable Audit Export Package",
    `Generated At: ${generatedAt}`,
    `Batch ID: ${batch.id}`,
    "",
    "Contents:",
    "- batch-manifest.json: batch metadata and summary.",
    "- batch-manifest.csv: QR-level batch manifest.",
    "- trace-events.json: formal lifecycle events.",
    "- event-chain.jsonl: hash-linked event chain.",
    "- policy-alerts.json: related anomaly and policy alerts.",
    "- integrity.json: file hashes and signed integrity envelope.",
    "",
    "Verification:",
    "1) Hash each file with SHA-256 and compare to integrity.json.fileHashes",
    "2) Recreate canonical integrity payload and compare integrityHash",
    "3) Verify signature using configured signing key/secret",
  ].join("\n");

  const zip = new JSZip();
  for (const [name, content] of Object.entries(files)) {
    zip.file(name, content);
  }

  const buffer = await zip.generateAsync({ type: "nodebuffer" });
  const fileName = `batch-${batch.id}-audit-package.zip`;

  return {
    fileName,
    buffer,
    metadata: {
      batchId: batch.id,
      generatedAt,
      qrCount: qrCodes.length,
      eventCount: chainRecords.length,
      alertCount: policyAlerts.length,
      chainRoot,
      integrityHash,
      signatureAlgorithm: signature.algorithm,
    },
  };
};
