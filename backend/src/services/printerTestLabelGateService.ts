import prisma from "../config/database";

const stableStringify = (value: unknown) =>
  JSON.stringify(value || {}, Object.keys((value || {}) as Record<string, unknown>).sort());

export const buildPrinterTestLabelFingerprint = (printer: any) => ({
  connectionType: printer.connectionType,
  deliveryMode: printer.deliveryMode || "DIRECT",
  nativePrinterId: printer.nativePrinterId || null,
  ipAddress: printer.ipAddress || null,
  host: printer.host || null,
  port: printer.port || null,
  printerUri: printer.printerUri || null,
  commandLanguage: printer.commandLanguage || null,
});

export const assertPrinterTestLabelConfirmed = (printer: any) => {
  const metadata = printer.metadata && typeof printer.metadata === "object" && !Array.isArray(printer.metadata)
    ? (printer.metadata as Record<string, unknown>)
    : {};
  if (!String(metadata.lastTestLabelConfirmedAt || "").trim()) {
    throw Object.assign(new Error("PRINTER_TEST_LABEL_REQUIRED"), {
      reason: "Send and confirm a live printer test label before starting production printing.",
      printer,
    });
  }
  if (
    metadata.lastTestLabelFingerprint &&
    stableStringify(metadata.lastTestLabelFingerprint) !== stableStringify(buildPrinterTestLabelFingerprint(printer))
  ) {
    throw Object.assign(new Error("PRINTER_TEST_LABEL_REQUIRED"), {
      reason: "Printer setup changed after the last test label. Send a new live printer test label before production printing.",
      printer,
    });
  }
};

export const markPrinterTestLabelConfirmed = async (params: {
  printer: any;
  confirmedAt: string;
  connectionType: string;
  deviceJobRef?: string | null;
}) => {
  const metadata = params.printer.metadata && typeof params.printer.metadata === "object" && !Array.isArray(params.printer.metadata)
    ? (params.printer.metadata as Record<string, unknown>)
    : {};
  await prisma.printer.update({
    where: { id: params.printer.id },
    data: {
      metadata: {
        ...metadata,
        lastTestLabelConfirmedAt: params.confirmedAt,
        lastTestLabelConnectionType: params.connectionType,
        lastTestLabelDeviceJobRef: params.deviceJobRef || null,
        lastTestLabelFingerprint: buildPrinterTestLabelFingerprint(params.printer),
      },
    },
  });
};
