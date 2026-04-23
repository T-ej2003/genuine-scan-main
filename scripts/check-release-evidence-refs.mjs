const normalize = (value) => String(value || "").trim();

const isPlaceholder = (value) => {
  const normalized = normalize(value).toLowerCase();
  if (!normalized) return true;
  return [
    "pending",
    "tbd",
    "todo",
    "unknown",
    "n/a",
    "none",
    "example",
    "placeholder",
    "deploy-log://rotation/jwt",
    "deploy-log://rotation/qr-signing",
  ].some((token) => normalized === token || normalized.includes(token));
};

const repository = normalize(process.env.GITHUB_REPOSITORY);
const ref = normalize(process.env.GITHUB_REF);
const enforceExplicit = normalize(process.env.REQUIRE_RELEASE_EVIDENCE_REFS).toLowerCase() === "true";
const isReleaseTag = ref.startsWith("refs/tags/release-") || ref.startsWith("refs/tags/v");
const enforce = enforceExplicit || isReleaseTag;

const requiredRefs = [
  { key: "PROVENANCE_BACKFILL_EVIDENCE_REF", value: process.env.PROVENANCE_BACKFILL_EVIDENCE_REF },
  { key: "SECRET_ROTATION_EVIDENCE_REF", value: process.env.SECRET_ROTATION_EVIDENCE_REF },
  { key: "INCIDENT_DRILL_EVIDENCE_REF", value: process.env.INCIDENT_DRILL_EVIDENCE_REF },
];

const failures = [];
const warnings = [];

for (const item of requiredRefs) {
  const value = normalize(item.value);
  if (isPlaceholder(value)) {
    const issue = {
      key: item.key,
      status: value ? "placeholder" : "missing",
    };
    if (enforce) failures.push(issue);
    else warnings.push(issue);
  }
}

const summary = {
  repository: repository || null,
  ref: ref || null,
  enforce,
  checkedAt: new Date().toISOString(),
  refs: Object.fromEntries(
    requiredRefs.map((item) => {
      const value = normalize(item.value);
      return [
        item.key,
        {
          configured: Boolean(value),
          status: isPlaceholder(value) ? (value ? "placeholder" : "missing") : "configured",
        },
      ];
    })
  ),
  warningCount: warnings.length,
  failureCount: failures.length,
};

console.log(JSON.stringify(summary, null, 2));
for (const warning of warnings) {
  console.warn(`warning: ${warning.key} is ${warning.status}`);
}

if (failures.length > 0) {
  console.error("Release evidence reference check failed:");
  for (const failure of failures) {
    console.error(`- ${failure.key} is ${failure.status}`);
  }
  process.exit(1);
}

console.log("Release evidence reference check passed.");
