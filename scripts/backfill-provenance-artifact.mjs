import { spawnSync } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";

const hasFlag = (name) => process.argv.includes(name);
const readArg = (name) => {
  const index = process.argv.indexOf(name);
  if (index === -1) return null;
  return process.argv[index + 1] || null;
};

const execute = hasFlag("--execute");
const limitArg = Number(readArg("--limit") || "");
const limit = Number.isFinite(limitArg) && limitArg > 0 ? Math.floor(limitArg) : 1000;
const mode = execute ? "exec" : "dryrun";
const timestamp = new Date().toISOString().replace(/[:.]/g, "-");

const artifactDir = path.resolve(process.cwd(), "audit-artifacts", "provenance");
mkdirSync(artifactDir, { recursive: true });
const artifactPath = path.join(artifactDir, `backfill-${mode}-${timestamp}.json`);

const envPath = String(process.env.PATH || "")
  .split(":")
  .filter(Boolean);
for (const entry of ["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin", "/bin", "/usr/sbin", "/sbin"]) {
  if (!envPath.includes(entry)) envPath.unshift(entry);
}

const args = ["--prefix", "backend", "run", "data:backfill-qr-provenance", "--", "--limit", String(limit), "--json"];
if (execute) args.push("--execute");

const result = spawnSync("npm", args, {
  encoding: "utf8",
  env: {
    ...process.env,
    PATH: envPath.join(":"),
  },
});

if (result.error) {
  throw result.error;
}
if (result.status !== 0) {
  const output = `${result.stdout || ""}\n${result.stderr || ""}`.trim();
  throw new Error(`QR provenance backfill command failed.\n${output}`);
}

const output = String(result.stdout || "").trim();
let payload;
try {
  payload = JSON.parse(output);
} catch {
  payload = {
    mode,
    parsed: false,
    rawOutput: output,
  };
}

const envelope = {
  generatedAt: new Date().toISOString(),
  mode,
  command: `npm ${args.join(" ")}`,
  payload,
};

writeFileSync(artifactPath, `${JSON.stringify(envelope, null, 2)}\n`, "utf8");
console.log(`Provenance backfill artifact written: ${artifactPath}`);

