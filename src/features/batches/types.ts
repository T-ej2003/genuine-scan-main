export type BatchRow = {
  id: string;
  name: string;
  licenseeId: string;
  manufacturerId?: string | null;
  batchKind?: "RECEIVED_PARENT" | "MANUFACTURER_CHILD";
  parentBatchId?: string | null;
  rootBatchId?: string | null;
  startCode: string;
  endCode: string;
  totalCodes: number;
  printedAt: string | null;
  createdAt: string;
  updatedAt?: string;
  licensee?: { id: string; name: string; prefix: string } | null;
  manufacturer?: { id: string; name: string; email: string } | null;
  _count?: { qrCodes: number };
  availableCodes?: number;
  unassignedRemainingCodes?: number;
  assignedCodes?: number;
  printableCodes?: number;
  printedCodes?: number;
  redeemedCodes?: number;
  blockedCodes?: number;
  remainingStartCode?: string | null;
  remainingEndCode?: string | null;
};

export type ManufacturerRow = { id: string; name: string; email: string; isActive: boolean };

export type QrRow = {
  code: string;
  batchId?: string | null;
  batch?: { id: string } | null;
};

export type TraceEventType = "COMMISSIONED" | "ASSIGNED" | "PRINTED" | "REDEEMED" | "BLOCKED";

export type TraceEventRow = {
  id: string;
  eventType?: TraceEventType;
  action?: string;
  sourceAction?: string | null;
  createdAt: string;
  details?: any;
  user?: { id: string; name?: string | null; email?: string | null } | null;
  manufacturer?: { id: string; name?: string | null; email?: string | null } | null;
  qrCode?: { id: string; code?: string | null } | null;
  userId?: string | null;
};

export type AuditLogRow = {
  id: string;
  action?: string;
  entityType?: string | null;
  entityId?: string | null;
  createdAt: string;
  details?: any;
  user?: { id: string; name?: string | null; email?: string | null } | null;
  userId?: string | null;
};

export type PrinterConnectionStatus = {
  connected: boolean;
  trusted: boolean;
  compatibilityMode: boolean;
  degraded?: boolean;
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
  capabilitySummary?: {
    transports: string[];
    protocols: string[];
    languages: string[];
    supportsRaster: boolean;
    supportsPdf: boolean;
    dpiOptions: number[];
    mediaSizes: string[];
  } | null;
  printers?: Array<{
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
  }>;
  calibrationProfile?: Record<string, unknown> | null;
  error?: string | null;
};

export type LocalPrinterRow = {
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
};

export type RegisteredPrinterRow = {
  id: string;
  name: string;
  vendor?: string | null;
  model?: string | null;
  connectionType: "LOCAL_AGENT" | "NETWORK_DIRECT" | "NETWORK_IPP";
  commandLanguage:
    | "AUTO"
    | "ZPL"
    | "TSPL"
    | "SBPL"
    | "EPL"
    | "DPL"
    | "HONEYWELL_DP"
    | "HONEYWELL_FINGERPRINT"
    | "IPL"
    | "ZSIM"
    | "CPCL"
    | "ESC_POS"
    | "OTHER";
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
};

export type PrinterNoticeTone = "success" | "warning" | "neutral" | "danger";

export type PrinterSelectionNotice = {
  title: string;
  summary: string;
  detail: string;
  tone: PrinterNoticeTone;
};

export type PrintJobRow = {
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
  printer?: {
    id?: string;
    name?: string | null;
    connectionType?: "LOCAL_AGENT" | "NETWORK_DIRECT" | "NETWORK_IPP" | string | null;
    commandLanguage?: string;
  } | null;
  session?: {
    id?: string;
    status?: string;
    totalItems?: number;
    confirmedItems?: number;
    frozenItems?: number;
    failedReason?: string | null;
    remainingToPrint?: number;
    awaitingConfirmationCount?: number;
    counts?: Record<string, number>;
  } | null;
};
