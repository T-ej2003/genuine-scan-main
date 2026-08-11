import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";

const ROOT = path.resolve(import.meta.dirname, "../..");
const PTY_HELPER = path.join(ROOT, "scripts/aws/ecs-exec-fixture-pty.py");
const shellQuote = (value) => `'${String(value).replaceAll("'", "'\\''")}'`;
const SAFE = /^[A-Za-z0-9._:/=@+?,%\- ]+$/;

const cleanTranscript = (value) => String(value || "").replace(/\x1B\[[0-?]*[ -/]*[@-~]/g, "");

export function createProductionInteractiveEcsExecRunner({ spawn, region = "eu-west-2", maxBuffer = 4 * 1024 * 1024 } = {}) {
  if (typeof spawn !== "function") throw new Error("Process-scoped verifier spawn adapter is required.");
  return async ({ cluster, taskArn, container, command, inputFile } = {}) => {
    if (![region, cluster, taskArn, container].every((value) => typeof value === "string" && SAFE.test(value))) throw new Error("ECS Exec target contains unsupported characters.");
    if (typeof command !== "string" || !command || command.includes("\n") || command.includes("\r")) throw new Error("ECS Exec command is not a fixed single-line runtime command.");
    const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-ecs-exec-"));
    const fixture = path.join(directory, "fixture");
    try {
      writeFileSync(fixture, inputFile ? requireFixture(inputFile) : Buffer.alloc(0), { mode: 0o600 });
      const remoteCommand = `printf MSCQR_FIXTURE_READY; ${command}`;
      const result = spawn("python3", [
        PTY_HELPER, "--input-file", fixture, "150", String(maxBuffer), "--",
        "aws", "ecs", "execute-command", "--region", region, "--cluster", cluster,
        "--task", taskArn, "--container", container, "--interactive", "--command", `sh -c ${shellQuote(remoteCommand)}`,
      ], { cwd: ROOT, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"], maxBuffer });
      if (result.error || result.status !== 0) throw new Error("ECS Exec runtime command failed.");
      return cleanTranscript(result.stdout);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  };
}

function requireFixture(filePath) {
  if (typeof filePath !== "string" || !path.isAbsolute(filePath)) throw new Error("ECS Exec fixture path must be absolute.");
  return readFileSync(filePath);
}

export function extractMarkedJson(transcript, begin, end) {
  const clean = cleanTranscript(transcript);
  const start = clean.indexOf(begin);
  const finish = clean.indexOf(end, start + begin.length);
  if (start < 0 || finish < 0) throw new Error("ECS Exec runtime evidence markers are missing.");
  try { return JSON.parse(clean.slice(start + begin.length, finish).trim()); } catch { throw new Error("ECS Exec runtime evidence is malformed."); }
}
