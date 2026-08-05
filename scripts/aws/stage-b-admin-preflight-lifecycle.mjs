import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawn as defaultSpawn } from "node:child_process";

export const STAGE_B_ADMIN_PREFLIGHT_TIMEOUT_SECONDS = 1200;
export const STAGE_B_ADMIN_PREFLIGHT_TIMEOUT_MS = STAGE_B_ADMIN_PREFLIGHT_TIMEOUT_SECONDS * 1000;
export const STAGE_B_ADMIN_PREFLIGHT_TERMINATION_GRACE_MS = 5000;
export const STAGE_B_ADMIN_PREFLIGHT_LIFECYCLE_STATES = Object.freeze(["RUNNING", "SUCCEEDED", "FAILED", "TIMED_OUT"]);

const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const safeCredentialPattern = /((?:AWS_(?:ACCESS_KEY_ID|SECRET_ACCESS_KEY|SESSION_TOKEN)|AccessKeyId|SecretAccessKey|SessionToken)\s*[=:]\s*)[^\s,;]+/gi;

const redact = (value) => String(value).replace(safeCredentialPattern, "$1<redacted>");
const isPlainFile = (filePath) => {
  const stat = fs.lstatSync(filePath, { throwIfNoEntry: false });
  return Boolean(stat?.isFile() && !stat.isSymbolicLink());
};
const mode = (stat) => stat.mode & 0o777;
const assertExternalPath = (filePath, repositoryRoot) => {
  const relative = path.relative(path.resolve(repositoryRoot), path.resolve(filePath));
  if (!relative || (!relative.startsWith("..") && !path.isAbsolute(relative))) throw new Error("Administrator preflight lifecycle directory must be outside the repository.");
};
const assertPrivateDirectory = (directory) => {
  const resolved = path.resolve(directory);
  const stat = fs.lstatSync(resolved, { throwIfNoEntry: false });
  if (!stat || !stat.isDirectory() || stat.isSymbolicLink() || mode(stat) !== 0o700) throw new Error("Administrator preflight lifecycle directory must be a non-symlink directory with mode 0700.");
  return resolved;
};
const ensurePrivateDirectory = (directory) => {
  const resolved = path.resolve(directory);
  const stat = fs.lstatSync(resolved, { throwIfNoEntry: false });
  if (!stat) {
    fs.mkdirSync(resolved, { recursive: false, mode: 0o700 });
    fs.chmodSync(resolved, 0o700);
  }
  return assertPrivateDirectory(resolved);
};
const writeAtomic = (filePath, bytes) => {
  const parent = path.dirname(filePath);
  const temporary = path.join(parent, `.stage-b-lifecycle-${process.pid}-${crypto.randomBytes(6).toString("hex")}`);
  fs.writeFileSync(temporary, bytes, { flag: "wx", mode: 0o600 });
  fs.chmodSync(temporary, 0o600);
  const current = fs.lstatSync(filePath, { throwIfNoEntry: false });
  if (current?.isSymbolicLink()) {
    fs.unlinkSync(temporary);
    throw new Error("Administrator preflight lifecycle metadata must not be a symlink.");
  }
  fs.renameSync(temporary, filePath);
  fs.chmodSync(filePath, 0o600);
};
const writePrivateBytes = (filePath, bytes) => {
  const temporary = `${filePath}.tmp-${process.pid}-${crypto.randomBytes(6).toString("hex")}`;
  fs.writeFileSync(temporary, bytes, { flag: "wx", mode: 0o600 });
  fs.chmodSync(temporary, 0o600);
  const current = fs.lstatSync(filePath, { throwIfNoEntry: false });
  if (current?.isSymbolicLink()) {
    fs.unlinkSync(temporary);
    throw new Error("Administrator preflight lifecycle output must not be a symlink.");
  }
  fs.renameSync(temporary, filePath);
  fs.chmodSync(filePath, 0o600);
  return { path: filePath, sha256: sha256(bytes) };
};
const writeJson = (filePath, value) => writeAtomic(filePath, Buffer.from(`${JSON.stringify(value, null, 2)}\n`));
const readJson = (filePath) => JSON.parse(fs.readFileSync(filePath, "utf8"));
const nowIso = (now) => new Date(now()).toISOString();
const canonicalizeJson = (value) => Array.isArray(value)
  ? `[${value.map(canonicalizeJson).join(",")}]`
  : value && typeof value === "object"
    ? `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalizeJson(value[key])}`).join(",")}}`
    : JSON.stringify(value);
const processIsAlive = (pid, processOps = process) => {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try {
    processOps.kill(pid, 0);
    return true;
  } catch (error) {
    return error?.code === "EPERM";
  }
};

export function classifyStageBAdminPreflightDeadline({ active, elapsedSeconds }) {
  if (!active) return null;
  if (!Number.isFinite(elapsedSeconds) || elapsedSeconds < 0) throw new Error("Administrator preflight elapsed time is malformed.");
  return elapsedSeconds >= STAGE_B_ADMIN_PREFLIGHT_TIMEOUT_SECONDS ? "TIMED_OUT" : "RUNNING";
}

function acquireLifecycleLock({ lifecycleDirectory, lifecycleStatePath, retry, now, processOps }) {
  const lockPath = path.join(lifecycleDirectory, "lifecycle.lock");
  const existingState = fs.lstatSync(lifecycleStatePath, { throwIfNoEntry: false }) ? readJson(lifecycleStatePath) : null;
  let terminalState = existingState;
  if (existingState?.state === "RUNNING" && processIsAlive(existingState.pid, processOps)) throw new Error(`Administrator preflight producer is already running: pid=${existingState.pid}.`);
  if (existingState?.state === "RUNNING") {
    terminalState = { ...existingState, state: "FAILED", endedAt: nowIso(now), exitCode: null, timeout: false, failureClass: "ORPHANED_PROCESS", failure: "Producer PID is no longer active without a terminal lifecycle result." };
    writeJson(lifecycleStatePath, terminalState);
  }
  const lock = fs.lstatSync(lockPath, { throwIfNoEntry: false });
  if (lock) {
    if (lock.isSymbolicLink() || !lock.isFile()) throw new Error("Administrator preflight lifecycle lock is malformed.");
    if (mode(lock) !== 0o600) throw new Error("Administrator preflight lifecycle lock must have mode 0600.");
    if (terminalState?.pid && processIsAlive(terminalState.pid, processOps)) throw new Error(`Administrator preflight producer PID remains active: pid=${terminalState.pid}.`);
    if (!retry || !terminalState || !STAGE_B_ADMIN_PREFLIGHT_LIFECYCLE_STATES.includes(terminalState.state) || terminalState.state === "RUNNING") throw new Error("Administrator preflight lifecycle is terminal; an explicit retry is required.");
    fs.unlinkSync(lockPath);
  } else if (terminalState && (!retry || !STAGE_B_ADMIN_PREFLIGHT_LIFECYCLE_STATES.includes(terminalState.state) || terminalState.state === "RUNNING")) {
    throw new Error("Administrator preflight lifecycle already exists; use an explicit retry only after a terminal state.");
  }
  fs.writeFileSync(lockPath, `${JSON.stringify({ invocationId: crypto.randomUUID(), acquiredAt: nowIso(now) })}\n`, { flag: "wx", mode: 0o600 });
  fs.chmodSync(lockPath, 0o600);
  return lockPath;
}

function validatePublishedPair({ reportPath, signaturePath }) {
  for (const [filePath, label] of [[reportPath, "Administrator capability report"], [signaturePath, "Administrator capability signature"]]) {
    if (!isPlainFile(filePath)) throw new Error(`${label} must be a regular non-symlink file after producer exit.`);
    const stat = fs.lstatSync(filePath);
    if (mode(stat) !== 0o600) throw new Error(`${label} must have mode 0600 after producer exit.`);
  }
  const report = readJson(reportPath);
  const signature = readJson(signaturePath);
  if (report?.status !== "valid") throw new Error("Administrator capability report is not valid after producer exit.");
  const reportHash = sha256(Buffer.from(canonicalizeJson(report)));
  if (signature?.reportSha256 !== reportHash) throw new Error("Administrator capability signature is not bound to the published report.");
  return { reportSha256: reportHash, signatureSha256: sha256(fs.readFileSync(signaturePath)) };
}

function spawnProducer({ producerPath, producerArgs, cwd, env, spawn }) {
  return spawn(process.execPath, [producerPath, ...producerArgs], {
    cwd,
    env: { ...env },
    stdio: ["ignore", "pipe", "pipe"],
  });
}

async function waitForProducer(child, { timeoutMs, terminationGraceMs, setTimer = setTimeout, clearTimer = clearTimeout }) {
  const completion = new Promise((resolve) => {
    child.once("close", (code, signal) => resolve({ code, signal }));
    child.once("error", (error) => resolve({ error: redact(error.message) }));
  });
  let timeoutHandle;
  const timeout = new Promise((resolve) => {
    timeoutHandle = setTimer(() => resolve({ timedOut: true }), timeoutMs);
  });
  const first = await Promise.race([completion.then((result) => ({ ...result, timedOut: false })), timeout]);
  if (!first.timedOut) {
    clearTimer(timeoutHandle);
    return first;
  }
  child.kill("SIGTERM");
  const forceKill = new Promise((resolve) => setTimer(() => {
    child.kill("SIGKILL");
    resolve({ code: null, signal: "SIGKILL", forcedTermination: true });
  }, terminationGraceMs));
  const terminated = await Promise.race([completion, forceKill]);
  return { ...terminated, timedOut: true };
}

export async function runStageBAdminPreflightLifecycle({
  lifecycleDirectory,
  outputPath,
  signaturePath,
  producerPath,
  phase = null,
  producerArgs = ["--identity", "administrator"],
  cwd,
  repositoryRoot,
  env = process.env,
  now = Date.now,
  spawn = defaultSpawn,
  processOps = process,
  timeoutMs = STAGE_B_ADMIN_PREFLIGHT_TIMEOUT_MS,
  terminationGraceMs = STAGE_B_ADMIN_PREFLIGHT_TERMINATION_GRACE_MS,
  retry = false,
} = {}) {
  if (!repositoryRoot) throw new Error("Administrator preflight lifecycle repository root is required.");
  assertExternalPath(lifecycleDirectory, repositoryRoot);
  const directory = ensurePrivateDirectory(lifecycleDirectory);
  const lifecycleStatePath = path.join(directory, "lifecycle.json");
  const stdoutPath = path.join(directory, "stdout.log");
  const stderrPath = path.join(directory, "stderr.log");
  const lockPath = acquireLifecycleLock({ lifecycleDirectory: directory, lifecycleStatePath, retry, now, processOps });
  const startedAt = nowIso(now);
  const safeProducerArgs = producerArgs.map((argument) => redact(argument));
  let child;
  let releaseLock = true;
  try {
    child = spawnProducer({ producerPath, producerArgs, cwd, env, spawn });
    const pid = child.pid;
    if (!Number.isInteger(pid) || pid <= 0) throw new Error("Administrator preflight producer did not expose a valid PID.");
    writeJson(lifecycleStatePath, { schemaVersion: 1, phase, state: "RUNNING", pid, invocationId: crypto.randomUUID(), command: process.execPath, arguments: safeProducerArgs, startedAt, timeoutSeconds: STAGE_B_ADMIN_PREFLIGHT_TIMEOUT_SECONDS });
    const stdout = []; const stderr = [];
    child.stdout?.on("data", (chunk) => stdout.push(Buffer.from(chunk)));
    child.stderr?.on("data", (chunk) => stderr.push(Buffer.from(chunk)));
    const result = await waitForProducer(child, { timeoutMs, terminationGraceMs });
    const endedAt = nowIso(now);
    const stdoutFile = writePrivateBytes(stdoutPath, Buffer.from(redact(Buffer.concat(stdout).toString("utf8"))));
    const stderrFile = writePrivateBytes(stderrPath, Buffer.from(redact(Buffer.concat(stderr).toString("utf8"))));
    if (result.timedOut) {
      releaseLock = !result.forcedTermination;
      const lifecycle = { schemaVersion: 1, phase, state: "TIMED_OUT", pid, invocationId: readJson(lifecycleStatePath).invocationId, command: process.execPath, arguments: safeProducerArgs, startedAt, endedAt, exitCode: result.code, signal: result.signal, timeout: true, stdout: stdoutFile, stderr: stderrFile };
      writeJson(lifecycleStatePath, lifecycle);
      return lifecycle;
    }
    if (result.error) {
      const lifecycle = { schemaVersion: 1, phase, state: "FAILED", pid, invocationId: readJson(lifecycleStatePath).invocationId, command: process.execPath, arguments: safeProducerArgs, startedAt, endedAt, exitCode: null, signal: null, timeout: false, failureClass: "LOCAL_RUNTIME", failure: result.error, stdout: stdoutFile, stderr: stderrFile };
      writeJson(lifecycleStatePath, lifecycle);
      return lifecycle;
    }
    if (result.code !== 0) {
      const lifecycle = { schemaVersion: 1, phase, state: "FAILED", pid, invocationId: readJson(lifecycleStatePath).invocationId, command: process.execPath, arguments: safeProducerArgs, startedAt, endedAt, exitCode: result.code, signal: result.signal, timeout: false, failureClass: "PRODUCER_EXIT", stdout: stdoutFile, stderr: stderrFile };
      writeJson(lifecycleStatePath, lifecycle);
      return lifecycle;
    }
    let pair;
    try { pair = validatePublishedPair({ reportPath: outputPath, signaturePath }); } catch (error) {
      const lifecycle = { schemaVersion: 1, phase, state: "FAILED", pid, invocationId: readJson(lifecycleStatePath).invocationId, command: process.execPath, arguments: safeProducerArgs, startedAt, endedAt, exitCode: result.code, signal: result.signal, timeout: false, failureClass: "TRANSACTIONAL_PUBLICATION", failure: error.message, stdout: stdoutFile, stderr: stderrFile };
      writeJson(lifecycleStatePath, lifecycle);
      return lifecycle;
    }
    const lifecycle = { schemaVersion: 1, phase, state: "SUCCEEDED", pid, invocationId: readJson(lifecycleStatePath).invocationId, command: process.execPath, arguments: safeProducerArgs, startedAt, endedAt, exitCode: result.code, signal: result.signal, timeout: false, report: { path: outputPath, ...pair }, signature: { path: signaturePath, sha256: pair.signatureSha256 }, stdout: stdoutFile, stderr: stderrFile };
    writeJson(lifecycleStatePath, lifecycle);
    return lifecycle;
  } catch (error) {
    if (child?.pid && processIsAlive(child.pid, processOps)) { child.kill("SIGTERM"); releaseLock = false; }
    const lifecycle = { schemaVersion: 1, phase, state: "FAILED", pid: child?.pid ?? null, command: process.execPath, arguments: safeProducerArgs, startedAt, endedAt: nowIso(now), exitCode: null, signal: null, timeout: false, failureClass: "LOCAL_RUNTIME", failure: redact(error.message) };
    writeJson(lifecycleStatePath, lifecycle);
    return lifecycle;
  } finally {
    if (releaseLock && isPlainFile(lockPath)) fs.unlinkSync(lockPath);
  }
}
