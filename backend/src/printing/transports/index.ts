import { PrinterTransportKind } from "@prisma/client";

export type TransportSubmitContext = {
  printerId: string;
  host?: string | null;
  port?: number | null;
  printerUri?: string | null;
  payload: string | Buffer;
};

export type PrinterTransportAdapter = {
  kind: PrinterTransportKind;
  liveEnabled: boolean;
  description: string;
  submit: (context: TransportSubmitContext) => Promise<void>;
};

export const PRINTER_TRANSPORT_ADAPTERS: Record<string, PrinterTransportAdapter> = {
  [PrinterTransportKind.RAW_TCP]: {
    kind: PrinterTransportKind.RAW_TCP,
    liveEnabled: true,
    description: "Direct raw TCP submission to certified industrial printers.",
    async submit() {
      throw new Error("RAW_TCP submission is handled by the network-direct dispatcher.");
    },
  },
  [PrinterTransportKind.DRIVER_QUEUE]: {
    kind: PrinterTransportKind.DRIVER_QUEUE,
    liveEnabled: true,
    description: "Controlled workstation spooler/driver queue path via the local agent.",
    async submit() {
      throw new Error("DRIVER_QUEUE submission is handled by the local print agent worker.");
    },
  },
  [PrinterTransportKind.SITE_GATEWAY]: {
    kind: PrinterTransportKind.SITE_GATEWAY,
    liveEnabled: true,
    description: "Private-LAN site gateway pull model for IPP-capable devices.",
    async submit() {
      throw new Error("SITE_GATEWAY submission is handled by the gateway worker.");
    },
  },
  [PrinterTransportKind.WEB_API]: {
    kind: PrinterTransportKind.WEB_API,
    liveEnabled: true,
    description: "Backend-managed web/IPP submission path for printers that explicitly support it.",
    async submit() {
      throw new Error("WEB_API submission is handled by the network IPP dispatcher.");
    },
  },
  [PrinterTransportKind.USB_RAW]: {
    kind: PrinterTransportKind.USB_RAW,
    liveEnabled: false,
    description: "Certification-gated raw USB transport extension point.",
    async submit() {
      throw new Error("USB_RAW transport is not enabled in the initial production cut.");
    },
  },
  [PrinterTransportKind.SERIAL_RAW]: {
    kind: PrinterTransportKind.SERIAL_RAW,
    liveEnabled: false,
    description: "Certification-gated serial transport extension point.",
    async submit() {
      throw new Error("SERIAL_RAW transport is not enabled in the initial production cut.");
    },
  },
  [PrinterTransportKind.VENDOR_SDK]: {
    kind: PrinterTransportKind.VENDOR_SDK,
    liveEnabled: false,
    description: "Certification-gated vendor SDK extension point.",
    async submit() {
      throw new Error("VENDOR_SDK transport is not enabled in the initial production cut.");
    },
  },
};
