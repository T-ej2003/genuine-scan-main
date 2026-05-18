import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

const repoRoot = path.resolve(new URL("../..", import.meta.url).pathname);
const scanner = path.join(repoRoot, "scripts/check-prisma-scope-guardrails.mjs");

test("Prisma scope scanner catches unsafe protected model access", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "scope-guardrail-"));
  const sample = path.join(tmp, "unsafe.ts");
  fs.writeFileSync(sample, "export const bad = () => prisma.user.findUnique({ where: { id } });\n");
  const result = spawnSync(process.execPath, [scanner, "--sample", sample], { encoding: "utf8" });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /prisma\.user\.findUnique/);
});

test("Prisma scope scanner permits explicitly documented safe exceptions", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "scope-guardrail-"));
  const sample = path.join(tmp, "safe.ts");
  fs.writeFileSync(
    sample,
    "// scope-guardrail-ignore: lookup is preceded by central scoped preflight.\nexport const ok = () => prisma.user.update({ where: { id }, data: {} });\n"
  );
  const result = spawnSync(process.execPath, [scanner, "--sample", sample], { encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr || result.stdout);
});

test("Prisma scope scanner rejects broad or undocumented allowlist entries", () => {
  const allowlist = path.join(repoRoot, "scripts/security-scope-allowlist.json");
  const original = fs.readFileSync(allowlist, "utf8");
  try {
    fs.writeFileSync(
      allowlist,
      JSON.stringify(
        {
          ignoredFiles: ["backend/src/controllers/userController.ts"],
          allowedFindings: [
            {
              path: "backend/src/controllers/*.ts",
              model: "user",
              methods: ["*"],
              reason: "safe",
            },
          ],
        },
        null,
        2
      )
    );
    const result = spawnSync(process.execPath, [scanner], { encoding: "utf8" });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /ignoredFiles is not allowed|exact path|cannotWidenAccess/);
  } finally {
    fs.writeFileSync(allowlist, original);
  }
});
