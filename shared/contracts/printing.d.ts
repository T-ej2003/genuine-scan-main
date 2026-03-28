export type PrinterCapabilitySummaryDTO = {
  transports: string[];
  protocols: string[];
  languages: string[];
  supportsRaster: boolean;
  supportsPdf: boolean;
  dpiOptions: number[];
  mediaSizes: string[];
  [key: string]: unknown;
};

export type LocalPrinterDTO = {
  printerId: string;
  printerName: string;
  model?: string | null;
  connection?: string | null;
  online?: boolean;
  isDefault?: boolean;
  protocols?: string[];
  languages?: string[];
  mediaSizes?: string[];
  dpi?: number | null;
  [key: string]: unknown;
};

export type PrinterConnectionStatusDTO = {
  connected: boolean;
  trusted: boolean;
  compatibilityMode: boolean;
  compatibilityReason?: string | null;
  eligibleForPrinting: boolean;
  connectionClass?: "TRUSTED" | "COMPATIBILITY" | "BLOCKED";
  stale: boolean;
  requiredForPrinting: boolean;
  trustStatus?: string;
  trustReason?: string | null;
  lastHeartbeatAt: string | null;
  ageSeconds: number | null;
  registrationId?: string | null;
  agentId?: string | null;
  deviceFingerprint?: string | null;
  mtlsFingerprint?: string | null;
  printerName?: string | null;
  printerId?: string | null;
  selectedPrinterId?: string | null;
  selectedPrinterName?: string | null;
  deviceName?: string | null;
  agentVersion?: string | null;
  capabilitySummary?: PrinterCapabilitySummaryDTO | null;
  printers?: LocalPrinterDTO[];
  calibrationProfile?: Record<string, unknown> | null;
  error?: string | null;
  [key: string]: unknown;
};

export type PrintJobSessionDTO = {
  id?: string;
  remainingToPrint?: number;
  confirmedItems?: number;
  frozenItems?: number;
  awaitingConfirmationCount?: number;
  counts?: Record<string, number>;
  [key: string]: unknown;
};

export type PrintJobDTO = {
  id: string;
  jobNumber?: string | null;
  status: "PENDING" | "SENT" | "CONFIRMED" | "FAILED" | "CANCELLED";
  pipelineState?:
    | "QUEUED"
    | "PREFLIGHT_OK"
    | "SENT_TO_PRINTER"
    | "PRINTER_ACKNOWLEDGED"
    | "PRINT_CONFIRMED"
    | "LOCKED"
    | "FAILED"
    | "NEEDS_OPERATOR_ACTION";
  printMode: "LOCAL_AGENT" | "NETWORK_DIRECT" | "NETWORK_IPP";
  quantity: number;
  itemCount?: number | null;
  reprintOfJobId?: string | null;
  reprintReason?: string | null;
  failureReason?: string | null;
  confirmationFailureReason?: string | null;
  awaitingConfirmation?: boolean;
  confirmationMode?: string | null;
  dispatchReferenceSummary?: {
    awaitingCount?: number;
    outstandingJobRefs?: string[];
  } | null;
  createdAt: string;
  updatedAt?: string;
  sentAt?: string | null;
  confirmedAt?: string | null;
  completedAt?: string | null;
  batch?: {
    id?: string;
    name?: string | null;
    licenseeId?: string | null;
  } | null;
  printer?: {
    id?: string;
    name?: string | null;
    connectionType?: string | null;
  } | null;
  session?: PrintJobSessionDTO | null;
  [key: string]: unknown;
};

export type RegisteredPrinterDTO = {
  id: string;
  name: string;
  vendor?: string | null;
  model?: string | null;
  connectionType: "LOCAL_AGENT" | "NETWORK_DIRECT" | "NETWORK_IPP";
  commandLanguage?: string | null;
  ipAddress?: string | null;
  host?: string | null;
  port?: number | null;
  resourcePath?: string | null;
  tlsEnabled?: boolean | null;
  printerUri?: string | null;
  deliveryMode?: "DIRECT" | "SITE_GATEWAY";
  nativePrinterId?: string | null;
  isActive: boolean;
  isDefault?: boolean;
  registryStatus?: {
    state: "READY" | "ATTENTION" | "OFFLINE" | "BLOCKED";
    summary: string;
    detail?: string | null;
  } | null;
  printerProfile?: Record<string, unknown> | null;
  latestDiscoverySnapshot?: Record<string, unknown> | null;
  capabilityDiscovery?: Record<string, unknown> | null;
  [key: string]: unknown;
};

export type DashboardNotificationDTO = {
  id: string;
  type?: string | null;
  title?: string | null;
  body?: string | null;
  createdAt?: string | null;
  readAt?: string | null;
  data?: unknown;
  incidentId?: string | null;
  [key: string]: unknown;
};
