import fs from "fs";
import os from "os";
import path from "path";

const markerPath = () => path.join(path.dirname(process.env.PRINT_AGENT_STATE_FILE || path.join(os.homedir(), ".mscqr", "local-print-agent-state.json")), "maintenance-fence.json");
let fenced = false;
let active = 0;

export const maintenanceFenced = () => {
  if (fenced) return true;
  try {
    fs.lstatSync(markerPath());
    fenced = true;
  } catch (error: any) {
    if (error?.code !== "ENOENT") fenced = true;
  }
  return fenced;
};

export const maintenanceCheckpoint = () => ({ fenced: maintenanceFenced(), active, idle: active === 0 });

export const enterMaintenanceFence = () => {
  fenced = true;
  const file = markerPath();
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  let fd: number | undefined;
  try {
    fd = fs.openSync(file, "wx", 0o600);
    fs.writeSync(fd, JSON.stringify({ version: 1, state: "FENCED", createdAt: new Date().toISOString() }));
    fs.fsyncSync(fd);
  } catch (error: any) {
    if (error?.code !== "EEXIST") throw error;
    if (!fs.lstatSync(file).isFile()) throw new Error("Existing maintenance fence is not a regular file.");
    const marker = JSON.parse(fs.readFileSync(file, "utf8"));
    if (marker?.version !== 1 || marker?.state !== "FENCED") throw new Error("Existing maintenance fence is invalid.");
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
  if (process.platform !== "win32") {
    const directory = fs.openSync(path.dirname(file), "r");
    try { fs.fsyncSync(directory); } finally { fs.closeSync(directory); }
  }
  return maintenanceCheckpoint();
};

export const runUnfencedWork = async <T>(work: () => Promise<T>): Promise<T> => {
  if (maintenanceFenced()) throw Object.assign(new Error("Connector maintenance fence prevents new print work."), { errorCode: "maintenance_fenced" });
  active += 1;
  try { return await work(); } finally { active -= 1; }
};
