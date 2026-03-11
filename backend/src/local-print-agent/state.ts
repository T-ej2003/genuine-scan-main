import { createHash, randomUUID } from "crypto";
import { promises as fs } from "fs";
import os from "os";
import path from "path";

export type CalibrationProfile = {
  dpi?: number;
  labelWidthMm?: number;
  labelHeightMm?: number;
  offsetXmm?: number;
  offsetYmm?: number;
  darkness?: number;
  speed?: number;
};

export type AgentState = {
  agentId: string;
  deviceFingerprint: string;
  selectedPrinterId: string | null;
  calibrationProfiles: Record<string, CalibrationProfile>;
};

const DEFAULT_STATE_FILE = path.join(os.homedir(), ".mscqr", "local-print-agent-state.json");
const LEGACY_STATE_FILE = path.join(os.homedir(), ".authenticqr", "local-print-agent-state.json");
const STATE_FILE = process.env.PRINT_AGENT_STATE_FILE || DEFAULT_STATE_FILE;

const sha256Hex = (value: string) => createHash("sha256").update(value).digest("hex");

const sanitizeCalibrationProfile = (value: unknown): CalibrationProfile => {
  const source = value && typeof value === "object" ? (value as Record<string, unknown>) : {};
  const toNumber = (key: keyof CalibrationProfile) => {
    const parsed = Number(source[key]);
    return Number.isFinite(parsed) ? parsed : undefined;
  };

  return {
    dpi: toNumber("dpi"),
    labelWidthMm: toNumber("labelWidthMm"),
    labelHeightMm: toNumber("labelHeightMm"),
    offsetXmm: toNumber("offsetXmm"),
    offsetYmm: toNumber("offsetYmm"),
    darkness: toNumber("darkness"),
    speed: toNumber("speed"),
  };
};

const buildDefaultState = (): AgentState => {
  const agentId = `agent-${randomUUID()}`;
  const deviceFingerprint = `device-${sha256Hex(`${os.hostname()}|${os.platform()}|${agentId}`).slice(0, 48)}`;
  return {
    agentId,
    deviceFingerprint,
    selectedPrinterId: null,
    calibrationProfiles: {},
  };
};

export const loadAgentState = async (): Promise<AgentState> => {
  try {
    let raw;
    try {
      raw = await fs.readFile(STATE_FILE, "utf8");
    } catch (error: any) {
      if (process.env.PRINT_AGENT_STATE_FILE || error?.code !== "ENOENT") throw error;
      raw = await fs.readFile(LEGACY_STATE_FILE, "utf8");
    }
    const parsed = JSON.parse(raw);
    const fallback = buildDefaultState();
    return {
      agentId: String(parsed?.agentId || fallback.agentId),
      deviceFingerprint: String(parsed?.deviceFingerprint || fallback.deviceFingerprint),
      selectedPrinterId: parsed?.selectedPrinterId ? String(parsed.selectedPrinterId) : null,
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
  } catch {
    const fallback = buildDefaultState();
    await saveAgentState(fallback);
    return fallback;
  }
};

export const saveAgentState = async (state: AgentState) => {
  await fs.mkdir(path.dirname(STATE_FILE), { recursive: true });
  await fs.writeFile(
    STATE_FILE,
    JSON.stringify(
      {
        agentId: state.agentId,
        deviceFingerprint: state.deviceFingerprint,
        selectedPrinterId: state.selectedPrinterId,
        calibrationProfiles: state.calibrationProfiles,
      },
      null,
      2
    ),
    "utf8"
  );
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
