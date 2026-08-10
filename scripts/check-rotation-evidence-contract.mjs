import path from "node:path";
import {
  readRotationEvidence,
  validateRotationEvidenceContract,
  validateRotationEvidenceFreshness,
} from "./security/rotation-evidence-contract.mjs";

const repoRoot = process.cwd();
const fixturePath = path.join(repoRoot, "scripts", "tests", "fixtures", "rotation-evidence-valid-stale.json");
const evidence = readRotationEvidence(fixturePath);
const contractFailures = validateRotationEvidenceContract(evidence);
if (contractFailures.length) {
  console.error("Rotation evidence contract check failed:");
  for (const failure of contractFailures) console.error(`- ${failure}`);
  process.exit(1);
}

const freshnessFailures = validateRotationEvidenceFreshness(evidence);
if (!freshnessFailures.some((failure) => failure.includes("is stale"))) {
  throw new Error("Source rotation contract fixture must remain stale so source and production gates cannot be conflated.");
}

console.log("ROTATION_CONTRACT_VALID=true");
console.log("ROTATION_EVIDENCE_FRESH=false");
console.log("PRODUCTION_ROTATION_CURRENT=false");
console.log("Source validation uses a non-production stale fixture; production evidence remains governed by check:rotation-evidence-freshness.");
