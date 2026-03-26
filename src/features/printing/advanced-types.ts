import { getPrinterDispatchLabel } from "@/lib/printer-user-facing";

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
  gatewayId?: string | null;
  gatewayStatus?: string | null;
  gatewayLastSeenAt?: string | null;
  gatewayProvisioningSecret?: string | null;
  nativePrinterId?: string | null;
  isActive: boolean;
  isDefault?: boolean;
  lastValidationStatus?: string | null;
  lastValidationMessage?: string | null;
  registryStatus?: {
    state: "READY" | "ATTENTION" | "OFFLINE" | "BLOCKED";
    summary: string;
    detail?: string | null;
  } | null;
  printerProfile?: Record<string, unknown> | null;
  latestDiscoverySnapshot?: Record<string, unknown> | null;
  capabilityDiscovery?: Record<string, unknown> | null;
};

export const NETWORK_DIRECT_SUPPORTED_LANGUAGES = [
  "ZPL",
  "TSPL",
  "SBPL",
  "EPL",
  "DPL",
  "HONEYWELL_DP",
  "HONEYWELL_FINGERPRINT",
  "IPL",
  "ZSIM",
  "CPCL",
] as const;
export type NetworkDirectCommandLanguage = (typeof NETWORK_DIRECT_SUPPORTED_LANGUAGES)[number];

export const NETWORK_DIRECT_LANGUAGE_LABELS: Record<NetworkDirectCommandLanguage, string> = {
  ZPL: "ZPL",
  TSPL: "TSPL",
  SBPL: "SBPL",
  EPL: "EPL",
  DPL: "DPL",
  HONEYWELL_DP: "Honeywell DP",
  HONEYWELL_FINGERPRINT: "Honeywell Fingerprint",
  IPL: "IPL",
  ZSIM: "ZSim",
  CPCL: "CPCL",
};

export const NETWORK_DIRECT_SUPPORTED_LANGUAGE_LABEL = NETWORK_DIRECT_SUPPORTED_LANGUAGES.map(
  (language) => NETWORK_DIRECT_LANGUAGE_LABELS[language]
).join(", ");

export const isSupportedNetworkDirectLanguage = (
  value: RegisteredPrinterRow["commandLanguage"] | string | null | undefined
): value is NetworkDirectCommandLanguage =>
  NETWORK_DIRECT_SUPPORTED_LANGUAGES.includes(String(value || "").trim().toUpperCase() as NetworkDirectCommandLanguage);

export const buildEmptyNetworkPrinterForm = () => ({
  connectionType: "NETWORK_DIRECT" as RegisteredPrinterRow["connectionType"],
  name: "",
  vendor: "",
  model: "",
  ipAddress: "",
  host: "",
  port: "9100",
  resourcePath: "/ipp/print",
  tlsEnabled: true,
  printerUri: "",
  deliveryMode: "DIRECT" as NonNullable<RegisteredPrinterRow["deliveryMode"]>,
  rotateGatewaySecret: false,
  commandLanguage: "ZPL" as RegisteredPrinterRow["commandLanguage"],
});

export type NetworkPrinterFormState = ReturnType<typeof buildEmptyNetworkPrinterForm>;

export const getManagedSetupTypeLabel = (params: {
  connectionType?: RegisteredPrinterRow["connectionType"] | null;
  deliveryMode?: RegisteredPrinterRow["deliveryMode"] | null;
}) => getPrinterDispatchLabel({ connectionType: params.connectionType, deliveryMode: params.deliveryMode });
