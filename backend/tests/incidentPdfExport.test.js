const { buildIncidentPdfBuffer } = require("../dist/services/incidentPdfService");

const assert = (condition, message) => {
  if (!condition) throw new Error(message);
};

const run = async () => {
  const incident = {
    id: "incident-1",
    qrCodeValue: "ACM00000001",
    status: "INVESTIGATING",
    severity: "HIGH",
    priority: "P2",
    incidentType: "DUPLICATE_SCAN",
    licenseeId: "lic-1",
    createdAt: "2026-03-01T10:00:00.000Z",
    updatedAt: "2026-03-01T10:20:00.000Z",
    consentToContact: true,
    customerName: "Ada",
    customerEmail: "ada@example.com",
    description: "Repeated scans reported by customer.",
    evidence: [
      {
        id: "ev-1",
        storageKey: "incident-1/photo-1.jpg",
        fileType: "image/jpeg",
        createdAt: "2026-03-01T10:05:00.000Z",
        uploadedBy: "CUSTOMER",
      },
    ],
    events: [
      {
        id: "evt-1",
        eventType: "CREATED",
        createdAt: "2026-03-01T10:00:00.000Z",
        actorType: "CUSTOMER",
        eventPayload: { source: "verify" },
      },
    ],
  };

  const buffer = await buildIncidentPdfBuffer(incident);
  assert(Buffer.isBuffer(buffer), "PDF export should return a buffer");
  assert(buffer.length > 500, "PDF buffer should not be empty");

  const header = buffer.subarray(0, 5).toString("utf8");
  assert(header === "%PDF-", "PDF output must start with %PDF-");

  const trailer = buffer.subarray(buffer.length - 256).toString("utf8");
  assert(trailer.includes("%%EOF"), "PDF output must contain EOF marker");

  console.log("incident PDF export tests passed");
};

run().catch((err) => {
  console.error(err);
  process.exit(1);
});
