import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const supported = new Set(["repair", "static", "ephemeral", "all-local"]);
const redact = (value) => String(value).replace(/\b(?:postgres|postgresql):\/\/[^\s'"`@/]+(?::[^\s'"`@]*)?@[^\s'"`]+/gi, "postgresql://<redacted>@<redacted>").replace(/\b(password|secret|token)\s*=\s*[^\s,;]+/gi, "$1=<redacted>");
const commandOutput = (command, args) => spawnSync(command, args, { cwd: root, encoding: "utf8", env: process.env });
const git = (args) => commandOutput("git", args).stdout.trim();
const markdown = (report) => ["# Local RLS run", "", `Result: ${report.result}`, `Database mutation occurred: ${report.databaseMutationOccurred}`, `Report path: ${report.reportPath}`, "", "| Phase | Status |", "|---|---|", ...report.phases.map((phase) => `| ${phase.name} | ${phase.status} |`), ""].join("\n");

const phasePlans = {
  repair: [["Production access scan", "node", ["scripts/rls/scan-production-access.mjs"]]],
  static: [
    ["Git validation", "git", ["diff", "--check"]], ["Backend build", "npm", ["--prefix", "backend", "run", "build"]],
    ["Named SQL function inventory", "node", ["scripts/rls/named-sql-function-inventory.mjs"]], ["Production access scan", "node", ["scripts/rls/scan-production-access.mjs"]], ["Context generation", "node", ["scripts/rls/context-boundary-plan.mjs"]],
    ["Workflow partition generation", "node", ["scripts/rls/generate-workflow-session-partition.mjs"]], ["SQL generation", "node", ["scripts/rls/generate-full-rls-sql.mjs"]], ["Package verification", "node", ["scripts/rls/verify-full-rls-package.mjs"]],
    ["Manifest validation", "node", ["scripts/rls/validate-manifests.mjs"]], ["Scope guardrails", "node", ["scripts/check-prisma-scope-guardrails.mjs"]],
    ["Full RLS verification", "npm", ["run", "rls:full-verify"]], ["Context check", "npm", ["run", "rls:context-check"]],
  ],
  ephemeral: [["Disposable database enforcement", "npm", ["run", "rls:full-verify"]]],
};
export const phasePlan = (phase) => phasePlans[phase] || [];

export const runLocalRls = (phase = "static", run = commandOutput) => {
  if (!supported.has(phase)) throw new Error(`Unsupported RLS phase '${phase}'. Only repair, static, ephemeral, and all-local are implemented locally; staging and production phases are intentionally not implemented.`);
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  const directory = path.join(root, "artifacts/rls-runs", stamp);
  fs.mkdirSync(directory, { recursive: true });
  const report = { branch: git(["branch", "--show-current"]), commitSha: git(["rev-parse", "HEAD"]), dirtyWorkingTree: Boolean(git(["status", "--porcelain"])), startedAt: new Date().toISOString(), finishedAt: null, phases: [], failedPhase: null, result: "RUNNING", databaseMutationOccurred: false, reportPath: path.relative(root, directory) };
  const names = phase === "all-local" ? ["repair", "static", "ephemeral"] : [phase];
  let log = "";
  for (const name of names) for (const [label, command, args] of phasePlan(name)) {
    const result = run(command, args);
    const output = redact(`${result.stdout || ""}${result.stderr || ""}`);
    log += `\n## ${label}\n$ ${command} ${args.join(" ")}\n${output}`;
    const status = result.status === 0 ? "PASS" : "FAIL";
    report.phases.push({ name: label, status });
    process.stdout.write(`${label.padEnd(30)} ${status}\n`);
    if (status === "FAIL") { report.failedPhase = label; report.result = "FAIL"; report.finishedAt = new Date().toISOString(); fs.writeFileSync(path.join(directory, "integration-check.log"), log); fs.writeFileSync(path.join(directory, "summary.json"), `${JSON.stringify(report, null, 2)}\n`); fs.writeFileSync(path.join(directory, "summary.md"), markdown(report)); return report; }
  }
  report.result = "PASS"; report.finishedAt = new Date().toISOString();
  fs.writeFileSync(path.join(directory, "integration-check.log"), log); fs.writeFileSync(path.join(directory, "summary.json"), `${JSON.stringify(report, null, 2)}\n`); fs.writeFileSync(path.join(directory, "summary.md"), markdown(report));
  return report;
};

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const index = process.argv.indexOf("--phase");
  const phase = index === -1 ? "static" : process.argv[index + 1];
  try { const report = runLocalRls(phase); if (report.result !== "PASS") { console.error(`Failed phase: ${report.failedPhase}; report: ${report.reportPath}`); process.exitCode = 1; } } catch (error) { console.error(redact(error.message)); process.exitCode = 1; }
}
