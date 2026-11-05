import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, randomUUID } from "crypto";
import { promises as fs } from "fs";
import os from "os";
import path from "path";

export type CalibrationProfile = {
  dpi?: number;
  labelWidthMm?: number;
  labelHeightMm?: number;
  offsetXmm?: number;
  offsetYmm?: number;
  qrTargetMm?: number;
  darkness?: number;
  speed?: number;
};

export type AgentState = {
  agentId: string;
  deviceFingerprint: string;
  selectedPrinterId: string | null;
  backendUrl: string | null;
  publicKeyPem: string;
  privateKeyPem: string;
  calibrationProfiles: Record<string, CalibrationProfile>;
};

const DEFAULT_STATE_FILE = path.join(os.homedir(), ".mscqr", "local-print-agent-state.json");
const LEGACY_STATE_FILE = path.join(os.homedir(), ".authenticqr", "local-print-agent-state.json");
const STATE_FILE = process.env.PRINT_AGENT_STATE_FILE || DEFAULT_STATE_FILE;

const sha256Hex = (value: string) => createHash("sha256").update(value).digest("hex");
const normalizeBackendUrl = (value: string | null) => {
  const trimmed = String(value || "").trim().replace(/\/+$/, "");
  return trimmed ? trimmed.replace(/\/api$/i, "") : null;
};

const sanitizeCalibrationProfile = (value: unknown): CalibrationProfile => {
  const source = value && typeof value === "object" ? (value as Record<string, unknown>) : {};
  const toNumber = (key: keyof CalibrationProfile) => {
    const parsed = Number(source[key]);
    return Number.isFinite(parsed) ? parsed : undefined;
  };

  return {
    ...source,
    dpi: toNumber("dpi"),
    labelWidthMm: toNumber("labelWidthMm"),
    labelHeightMm: toNumber("labelHeightMm"),
    offsetXmm: toNumber("offsetXmm"),
    offsetYmm: toNumber("offsetYmm"),
    qrTargetMm: toNumber("qrTargetMm"),
    darkness: toNumber("darkness"),
    speed: toNumber("speed"),
  };
};

const buildDefaultState = (): AgentState => {
  const agentId = `agent-${randomUUID()}`;
  const deviceFingerprint = `device-${sha256Hex(`${os.hostname()}|${os.platform()}|${agentId}`).slice(0, 48)}`;
  const keyPair = generateKeyPairSync("ed25519");
  return {
    agentId,
    deviceFingerprint,
    selectedPrinterId: null,
    backendUrl: null,
    publicKeyPem: keyPair.publicKey.export({ type: "spki", format: "pem" }).toString(),
    privateKeyPem: keyPair.privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    calibrationProfiles: {},
  };
};

const initializeAgentState = async (): Promise<AgentState> => {
  const initial = buildDefaultState();
  await fs.mkdir(path.dirname(STATE_FILE), { recursive: true });
  try {
    await fs.writeFile(STATE_FILE, JSON.stringify(initial, null, 2), { encoding: "utf8", mode: 0o600, flag: "wx" });
    return initial;
  } catch (error: any) {
    if (error?.code !== "EEXIST") throw error;
    return loadAgentState();
  }
};

export const loadAgentState = async (options: { initialize?: boolean } = {}): Promise<AgentState> => {
  let raw: string;
  try {
    raw = await fs.readFile(STATE_FILE, "utf8");
  } catch (error: any) {
    if (error?.code !== "ENOENT") throw error;
    if (process.env.PRINT_AGENT_STATE_FILE) {
      if (options.initialize === false) throw new Error("Existing connector identity is missing.");
      return initializeAgentState();
    }
    try {
      raw = await fs.readFile(LEGACY_STATE_FILE, "utf8");
    } catch (legacyError: any) {
      if (legacyError?.code !== "ENOENT") throw legacyError;
      if (options.initialize === false) throw new Error("Existing connector identity is missing.");
      return initializeAgentState();
    }
  }
  const parsed = JSON.parse(raw);
  for (const key of ["agentId", "deviceFingerprint", "publicKeyPem", "privateKeyPem"] as const) {
    if (typeof parsed?.[key] !== "string" || !parsed[key].trim()) {
      throw new Error("Connector identity is incomplete; preserve the state file and reconcile before starting.");
    }
  }
  try {
    const privateKey = createPrivateKey(parsed.privateKeyPem);
    const publicKey = createPublicKey(parsed.publicKeyPem);
    if (privateKey.asymmetricKeyType !== "ed25519" || publicKey.asymmetricKeyType !== "ed25519" ||
        !createPublicKey(privateKey).export({ type: "spki", format: "der" }).equals(publicKey.export({ type: "spki", format: "der" }))) {
      throw new Error("key mismatch");
    }
  } catch {
    throw new Error("Connector identity keys are invalid; preserve the state file and reconcile before starting.");
  }
  return {
    ...parsed,
    agentId: parsed.agentId,
    deviceFingerprint: parsed.deviceFingerprint,
    selectedPrinterId: parsed?.selectedPrinterId ? String(parsed.selectedPrinterId) : null,
    backendUrl: normalizeBackendUrl(parsed?.backendUrl ? String(parsed.backendUrl) : null),
    publicKeyPem: parsed.publicKeyPem,
    privateKeyPem: parsed.privateKeyPem,
    calibrationProfiles:
      parsed?.calibrationProfiles && typeof parsed.calibrationProfiles === "object"
        ? Object.fromEntries(
            Object.entries(parsed.calibrationProfiles as Record<string, unknown>).map(([printerId, profile]) => [
              printerId,
              sanitizeCalibrationProfile(profile),
            ])
          )
        : {},
  };
};

export const saveAgentState = async (state: AgentState) => {
  await fs.mkdir(path.dirname(STATE_FILE), { recursive: true });
  const temporaryFile = `${STATE_FILE}.${randomUUID()}.tmp`;
  try {
    await fs.writeFile(
      temporaryFile,
      JSON.stringify(
        {
          ...state,
          agentId: state.agentId,
          deviceFingerprint: state.deviceFingerprint,
          selectedPrinterId: state.selectedPrinterId,
          backendUrl: state.backendUrl,
          publicKeyPem: state.publicKeyPem,
          privateKeyPem: state.privateKeyPem,
          calibrationProfiles: state.calibrationProfiles,
        },
        null,
        2
      ),
      { encoding: "utf8", mode: 0o600, flag: "wx" }
    );
    await fs.rename(temporaryFile, STATE_FILE);
  } finally {
    await fs.rm(temporaryFile, { force: true });
  }
};

export const mergeCalibrationProfile = (
  state: AgentState,
  printerId: string,
  profile: CalibrationProfile
): AgentState => {
  const merged: CalibrationProfile = {
    ...(state.calibrationProfiles[printerId] || {}),
    ...sanitizeCalibrationProfile(profile),
  };
  return {
    ...state,
    calibrationProfiles: {
      ...state.calibrationProfiles,
      [printerId]: merged,
    },
  };
};

export const setAgentBackendUrl = (state: AgentState, backendUrl: string | null): AgentState => ({
  ...state,
  backendUrl: normalizeBackendUrl(backendUrl),
});
