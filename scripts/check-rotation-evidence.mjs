import { existsSync } from "node:fs";
import path from "node:path";
import { readRotationEvidence, validateRotationEvidence } from "./security/rotation-evidence-contract.mjs";

const repoRoot = process.cwd();
const evidencePath = path.join(repoRoot, ".security", "rotation-evidence.json");
const maxAgeDays = Number(String(process.env.ROTATION_EVIDENCE_MAX_AGE_DAYS || "").trim() || "120");

if (!existsSync(evidencePath)) throw new Error(`Missing rotation evidence file: ${path.relative(repoRoot, evidencePath)}`);

const failures = validateRotationEvidence(readRotationEvidence(evidencePath), {
  maxAgeDays,
  requireCleanup: String(process.env.ROTATION_WINDOW_COMPLETE || "").trim().toLowerCase() === "true",
});

if (failures.length) {
  console.error("Rotation evidence check failed:");
  for (const failure of failures) console.error(`- ${failure}`);
  process.exit(1);
}

console.log("Rotation evidence check passed.");
