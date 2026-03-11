import PDFDocument from "pdfkit";

const text = (value: unknown, fallback = "-") => {
  if (value == null) return fallback;
  const normalized = String(value).trim();
  return normalized || fallback;
};

const line = (doc: PDFKit.PDFDocument, label: string, value: unknown) => {
  doc.font("Helvetica-Bold").text(`${label}: `, { continued: true });
  doc.font("Helvetica").text(text(value));
};

const sectionTitle = (doc: PDFKit.PDFDocument, title: string) => {
  doc.moveDown(0.8);
  doc.font("Helvetica-Bold").fontSize(13).text(title);
  doc.moveDown(0.2);
};

const flattenPayload = (payload: unknown) => {
  if (!payload || typeof payload !== "object") return text(payload, "");
  return Object.entries(payload as Record<string, unknown>)
    .map(([k, v]) => `${k}: ${Array.isArray(v) ? v.join(", ") : text(v, "")}`)
    .join(" | ");
};

export const buildIncidentPdfBuffer = async (incident: any) => {
  const doc = new PDFDocument({
    size: "A4",
    margin: 42,
    info: {
      Title: `Incident ${text(incident?.id)}`,
      Author: "MSCQR",
      Subject: "Incident response export",
      Creator: "MSCQR backend",
    },
  });

  const chunks: Buffer[] = [];
  const done = new Promise<Buffer>((resolve, reject) => {
    doc.on("data", (chunk) => chunks.push(Buffer.from(chunk)));
    doc.on("end", () => resolve(Buffer.concat(chunks)));
    doc.on("error", (error) => reject(error));
  });

  doc.font("Helvetica-Bold").fontSize(18).text("Incident Response Export", { align: "left" });
  doc.moveDown(0.2);
  doc.font("Helvetica").fontSize(9).fillColor("#5b6470").text(`Generated at: ${new Date().toISOString()}`);
  doc.fillColor("#000000");

  sectionTitle(doc, "Reference");
  line(doc, "Incident ID", incident?.id);
  line(doc, "QR Code", incident?.qrCodeValue);
  line(doc, "Status", incident?.status);
  line(doc, "Severity", incident?.severity);
  line(doc, "Priority", incident?.priority);
  line(doc, "Type", incident?.incidentType);
  line(doc, "Licensee", incident?.licenseeId);
  line(doc, "Created", incident?.createdAt ? new Date(incident.createdAt).toISOString() : null);
  line(doc, "Updated", incident?.updatedAt ? new Date(incident.updatedAt).toISOString() : null);

  sectionTitle(doc, "Customer & Contact");
  line(doc, "Consent to contact", incident?.consentToContact ? "Yes" : "No");
  line(doc, "Customer name", incident?.customerName);
  line(doc, "Customer email", incident?.customerEmail);
  line(doc, "Customer phone", incident?.customerPhone);
  line(doc, "Country", incident?.customerCountry);
  line(doc, "Preferred contact", incident?.preferredContactMethod);

  sectionTitle(doc, "Description");
  doc.font("Helvetica").fontSize(10).text(text(incident?.description));
  doc.moveDown(0.4);
  line(doc, "Purchase place", incident?.purchasePlace);
  line(doc, "Purchase date", incident?.purchaseDate ? new Date(incident.purchaseDate).toISOString() : null);
  line(doc, "Product batch", incident?.productBatchNo);
  line(doc, "Location", incident?.locationName || incident?.locationCity || incident?.locationCountry || "-");

  sectionTitle(doc, "Workflow & Support");
  line(doc, "Workflow stage", incident?.handoff?.currentStage);
  line(doc, "Workflow SLA due", incident?.handoff?.slaDueAt ? new Date(incident.handoff.slaDueAt).toISOString() : null);
  line(doc, "Support ticket", incident?.supportTicket?.referenceCode || incident?.supportTicket?.id);
  line(doc, "Support status", incident?.supportTicket?.status);
  line(doc, "Support SLA due", incident?.supportTicket?.slaDueAt ? new Date(incident.supportTicket.slaDueAt).toISOString() : null);

  sectionTitle(doc, `Evidence (${Array.isArray(incident?.evidence) ? incident.evidence.length : 0})`);
  if (Array.isArray(incident?.evidence) && incident.evidence.length > 0) {
    incident.evidence.slice(0, 100).forEach((ev: any, idx: number) => {
      doc.font("Helvetica-Bold").text(`${idx + 1}. ${text(ev?.storageKey || ev?.fileType || ev?.id)}`);
      doc.font("Helvetica").fontSize(9);
      doc.text(`Type: ${text(ev?.fileType)}`);
      doc.text(`Created: ${ev?.createdAt ? new Date(ev.createdAt).toISOString() : "-"}`);
      doc.text(`By: ${text(ev?.uploadedBy)}`);
      doc.moveDown(0.2);
    });
  } else {
    doc.font("Helvetica").fontSize(10).text("No evidence attached.");
  }

  sectionTitle(doc, `Timeline (${Array.isArray(incident?.events) ? incident.events.length : 0})`);
  if (Array.isArray(incident?.events) && incident.events.length > 0) {
    incident.events.slice(0, 180).forEach((event: any, idx: number) => {
      const createdAt = event?.createdAt ? new Date(event.createdAt).toISOString() : "-";
      doc.font("Helvetica-Bold").fontSize(10).text(`${idx + 1}. ${text(event?.eventType)} @ ${createdAt}`);
      doc.font("Helvetica").fontSize(9).text(`Actor: ${text(event?.actorUser?.email || event?.actorType)}`);
      const payload = flattenPayload(event?.eventPayload);
      if (payload) {
        doc.text(`Details: ${payload}`);
      }
      doc.moveDown(0.2);
    });
  } else {
    doc.font("Helvetica").fontSize(10).text("No timeline events available.");
  }

  doc.end();
  return done;
};
