import { existsSync } from "node:fs";
import path from "node:path";
import {
  readRotationEvidence,
  validateRotationEvidenceFreshness,
  ROTATION_EVIDENCE_MAX_AGE_DAYS,
} from "./security/rotation-evidence-contract.mjs";

const repoRoot = process.cwd();
const evidencePath = path.join(repoRoot, ".security", "rotation-evidence.json");

if (!existsSync(evidencePath)) throw new Error(`Missing rotation evidence file: ${path.relative(repoRoot, evidencePath)}`);

const evidence = readRotationEvidence(evidencePath);
const failures = validateRotationEvidenceFreshness(evidence);
if (failures.length) {
  console.error("Rotation evidence freshness check failed:");
  for (const failure of failures) console.error(`- ${failure}`);
  console.error(`ROTATION_EVIDENCE_FRESH=false`);
  console.error(`MAX_ALLOWED_AGE_DAYS=${ROTATION_EVIDENCE_MAX_AGE_DAYS}`);
  process.exit(1);
}

console.log("ROTATION_EVIDENCE_FRESH=true");
console.log("PRODUCTION_ROTATION_CURRENT=true");
console.log(`MAX_ALLOWED_AGE_DAYS=${ROTATION_EVIDENCE_MAX_AGE_DAYS}`);
