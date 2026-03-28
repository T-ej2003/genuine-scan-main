import ipp from "ipp";

const DEFAULT_IPP_PORT = 631;
const REQUEST_TIMEOUT_MS = Math.max(2000, Math.min(20000, Number(process.env.NETWORK_IPP_TIMEOUT_MS || 8000) || 8000));

const normalizePath = (value?: string | null) => {
  const trimmed = String(value || "").trim();
  if (!trimmed) return "/ipp/print";
  return trimmed.startsWith("/") ? trimmed : `/${trimmed}`;
};

const toStringList = (value: unknown) => {
  if (Array.isArray(value)) return value.map((entry) => String(entry || "").trim()).filter(Boolean);
  const single = String(value || "").trim();
  return single ? [single] : [];
};

const toHttpScheme = (tlsEnabled: boolean) => (tlsEnabled ? "https" : "http");
const toIppScheme = (tlsEnabled: boolean) => (tlsEnabled ? "ipps" : "ipp");

export type IppPrinterProfile = {
  host?: string | null;
  port?: number | null;
  resourcePath?: string | null;
  tlsEnabled?: boolean | null;
  printerUri?: string | null;
};

export type IppConnectionInfo = {
  endpointUrl: string;
  printerUri: string;
  host: string;
  port: number;
  resourcePath: string;
  tlsEnabled: boolean;
};

export type IppPrinterInspection = {
  printerUri: string;
  endpointUrl: string;
  printerName: string | null;
  printerState: string | null;
  documentFormats: string[];
  uriSecurity: string[];
  ippVersions: string[];
  pdfSupported: boolean;
  raw: Record<string, unknown>;
};

export type IppJobInspection = {
  printerUri: string;
  endpointUrl: string;
  jobId: number;
  jobUri: string | null;
  jobState: number | null;
  jobStateReasons: string[];
  jobStateMessage: string | null;
  impressionsCompleted: number | null;
  mediaSheetsCompleted: number | null;
  pagesCompleted: number | null;
  raw: Record<string, unknown>;
};

export const buildIppConnectionInfo = (printer: IppPrinterProfile): IppConnectionInfo => {
  const explicitUri = String(printer.printerUri || "").trim();
  if (explicitUri) {
    const parsed = new URL(
      explicitUri.replace(/^ipp:\/\//i, "http://").replace(/^ipps:\/\//i, "https://")
    );
    const tlsEnabled = explicitUri.toLowerCase().startsWith("ipps://") || parsed.protocol === "https:";
    const resourcePath = normalizePath(parsed.pathname);
    const port = Number(parsed.port || DEFAULT_IPP_PORT) || DEFAULT_IPP_PORT;
    return {
      endpointUrl: `${toHttpScheme(tlsEnabled)}://${parsed.hostname}:${port}${resourcePath}`,
      printerUri: `${toIppScheme(tlsEnabled)}://${parsed.hostname}:${port}${resourcePath}`,
      host: parsed.hostname,
      port,
      resourcePath,
      tlsEnabled,
    };
  }

  const host = String(printer.host || "").trim();
  if (!host) {
    throw new Error("Network IPP printer host or FQDN is required.");
  }

  const tlsEnabled = Boolean(printer.tlsEnabled ?? true);
  const port = Math.max(1, Number(printer.port || DEFAULT_IPP_PORT) || DEFAULT_IPP_PORT);
  const resourcePath = normalizePath(printer.resourcePath);
  return {
    endpointUrl: `${toHttpScheme(tlsEnabled)}://${host}:${port}${resourcePath}`,
    printerUri: `${toIppScheme(tlsEnabled)}://${host}:${port}${resourcePath}`,
    host,
    port,
    resourcePath,
    tlsEnabled,
  };
};

const executeIppOperation = async (
  operation: string,
  message: Record<string, unknown> & { data?: Buffer },
  printer: IppConnectionInfo
) => {
  const client = ipp.Printer(printer.endpointUrl, {
    uri: printer.printerUri,
    charset: "utf-8",
    language: "en-us",
    version: "2.0",
  });

  return new Promise<Record<string, any>>((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(new Error(`IPP request timed out after ${REQUEST_TIMEOUT_MS}ms for ${printer.printerUri}`));
    }, REQUEST_TIMEOUT_MS);

    client.execute(operation, message, (error, response) => {
      clearTimeout(timer);
      if (error) return reject(error);
      resolve(response || {});
    });
  });
};

export const inspectIppPrinter = async (profile: IppPrinterProfile): Promise<IppPrinterInspection> => {
  const printer = buildIppConnectionInfo(profile);
  const response = await executeIppOperation(
    "Get-Printer-Attributes",
    {
      "operation-attributes-tag": {
        "attributes-charset": "utf-8",
        "attributes-natural-language": "en-us",
        "printer-uri": printer.printerUri,
        "requested-attributes": [
          "printer-name",
          "printer-state",
          "document-format-supported",
          "uri-security-supported",
          "ipp-versions-supported",
        ],
      },
    },
    printer
  );

  const attributes = (response["printer-attributes-tag"] || {}) as Record<string, unknown>;
  const documentFormats = toStringList(attributes["document-format-supported"]);
  const uriSecurity = toStringList(attributes["uri-security-supported"]);
  const ippVersions = toStringList(attributes["ipp-versions-supported"]);
  const printerName = String(attributes["printer-name"] || "").trim() || null;
  const printerState = String(attributes["printer-state"] || "").trim() || null;

  return {
    printerUri: printer.printerUri,
    endpointUrl: printer.endpointUrl,
    printerName,
    printerState,
    documentFormats,
    uriSecurity,
    ippVersions,
    pdfSupported: documentFormats.some((value) => value.toLowerCase() === "application/pdf"),
    raw: response,
  };
};

export const submitPdfToIppPrinter = async (params: {
  profile: IppPrinterProfile;
  pdf: Buffer;
  jobName: string;
  requestingUserName: string;
}) => {
  const printer = buildIppConnectionInfo(params.profile);
  const response = await executeIppOperation(
    "Print-Job",
    {
      "operation-attributes-tag": {
        "attributes-charset": "utf-8",
        "attributes-natural-language": "en-us",
        "printer-uri": printer.printerUri,
        "requesting-user-name": params.requestingUserName,
        "job-name": params.jobName,
        "document-format": "application/pdf",
      },
      data: params.pdf,
    },
    printer
  );

  const jobAttributes = (response["job-attributes-tag"] || {}) as Record<string, unknown>;
  return {
    printerUri: printer.printerUri,
    endpointUrl: printer.endpointUrl,
    jobId: Number(jobAttributes["job-id"] || 0) || null,
    jobUri: String(jobAttributes["job-uri"] || "").trim() || null,
    response,
  };
};

export const inspectIppJob = async (params: {
  profile: IppPrinterProfile;
  jobId: number;
}) => {
  const printer = buildIppConnectionInfo(params.profile);
  const response = await executeIppOperation(
    "Get-Job-Attributes",
    {
      "operation-attributes-tag": {
        "attributes-charset": "utf-8",
        "attributes-natural-language": "en-us",
        "printer-uri": printer.printerUri,
        "job-id": params.jobId,
        "requested-attributes": [
          "job-id",
          "job-uri",
          "job-state",
          "job-state-reasons",
          "job-state-message",
          "job-impressions-completed",
          "job-media-sheets-completed",
          "job-pages-completed",
        ],
      },
    },
    printer
  );

  const attributes = (response["job-attributes-tag"] || {}) as Record<string, unknown>;
  return {
    printerUri: printer.printerUri,
    endpointUrl: printer.endpointUrl,
    jobId: Number(attributes["job-id"] || params.jobId) || params.jobId,
    jobUri: String(attributes["job-uri"] || "").trim() || null,
    jobState: Number(attributes["job-state"] || 0) || null,
    jobStateReasons: toStringList(attributes["job-state-reasons"]),
    jobStateMessage: String(attributes["job-state-message"] || "").trim() || null,
    impressionsCompleted: Number(attributes["job-impressions-completed"] || 0) || null,
    mediaSheetsCompleted: Number(attributes["job-media-sheets-completed"] || 0) || null,
    pagesCompleted: Number(attributes["job-pages-completed"] || 0) || null,
    raw: response,
  } satisfies IppJobInspection;
};
