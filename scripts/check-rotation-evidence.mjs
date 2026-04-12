import { existsSync, readFileSync } from "node:fs";
import path from "node:path";

const repoRoot = process.cwd();
const evidencePath = path.join(repoRoot, ".security", "rotation-evidence.json");
const maxAgeDays = Number(String(process.env.ROTATION_EVIDENCE_MAX_AGE_DAYS || "").trim() || "120");

if (!existsSync(evidencePath)) {
  throw new Error(`Missing rotation evidence file: ${path.relative(repoRoot, evidencePath)}`);
}

const evidence = JSON.parse(readFileSync(evidencePath, "utf8"));
const failures = [];

const requiredTopLevel = ["recordedAt", "approvedBy", "approverRole", "reason", "ticket", "environment", "families"];
for (const key of requiredTopLevel) {
  if (!(key in evidence)) {
    failures.push(`rotation evidence missing required field: ${key}`);
  }
}

const recordedAt = new Date(String(evidence.recordedAt || ""));
if (Number.isNaN(recordedAt.getTime())) {
  failures.push("rotation evidence recordedAt must be a valid ISO date-time");
} else {
  const ageMs = Date.now() - recordedAt.getTime();
  if (ageMs > maxAgeDays * 24 * 60 * 60 * 1000) {
    failures.push(
      `rotation evidence is stale (${Math.floor(ageMs / (24 * 60 * 60 * 1000))} days old; max ${maxAgeDays})`
    );
  }
}

const families = Array.isArray(evidence.families) ? evidence.families : [];
if (!families.length) {
  failures.push("rotation evidence must include at least one rotated family");
}

const requiredFamilies = ["jwt_secrets", "qr_signing_keys"];
const presentFamilies = new Set(families.map((entry) => String(entry?.name || "").trim()));
for (const family of requiredFamilies) {
  if (!presentFamilies.has(family)) {
    failures.push(`rotation evidence missing required family entry: ${family}`);
  }
}

for (const [index, family] of families.entries()) {
  if (!String(family?.operator || "").trim()) {
    failures.push(`rotation evidence family[${index}] missing operator`);
  }
  if (!String(family?.rotatedAt || "").trim()) {
    failures.push(`rotation evidence family[${index}] missing rotatedAt`);
  } else {
    const rotatedAt = new Date(String(family.rotatedAt));
    if (Number.isNaN(rotatedAt.getTime())) {
      failures.push(`rotation evidence family[${index}] has invalid rotatedAt`);
    }
  }
}

if (failures.length > 0) {
  console.error("Rotation evidence check failed:");
  for (const failure of failures) console.error(`- ${failure}`);
  process.exit(1);
}

console.log("Rotation evidence check passed.");

