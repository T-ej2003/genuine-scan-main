export const AUTO_FAILOVER_DECISION_STATUSES = new Set(["NOOP", "RECOMMEND_FAILOVER", "BLOCKED_MANUAL_REVIEW"]);

export const REGION_RULES = {
  europe: {
    label: "Europe EU -> London",
    operation: "rollback-europe",
    manualOnly: false,
    matches(row) {
      return /^london_/i.test(row.check || "") || /London/i.test(row.scope || "");
    },
  },
  africa: {
    label: "Africa AF -> Cape Town",
    operation: "rollback-africa",
    manualOnly: false,
    matches(row) {
      return /^capetown_/i.test(row.check || "") || /Cape Town/i.test(row.scope || "");
    },
  },
  default: {
    label: "Default/global * -> Mumbai",
    operation: "",
    manualOnly: true,
    matches(row) {
      return /^mumbai_/i.test(row.check || "") || /Mumbai/i.test(row.scope || "");
    },
  },
};

export function normalizeTruthTableSample(sample, fallbackPath = "") {
  if (!sample || typeof sample !== "object") throw new Error("truth-table sample must be an object.");
  if (!Array.isArray(sample.rows)) throw new Error("truth-table sample is missing rows array.");
  return {
    generatedAt: sample.generatedAt || "",
    path: sample.path || fallbackPath,
    rows: sample.rows.map((row) => ({
      check: String(row.check || ""),
      scope: String(row.scope || ""),
      status: String(row.status || "").toUpperCase(),
      detail: String(row.detail || ""),
    })),
  };
}

export function evaluateAutoFailover(samples, options = {}) {
  const threshold = Number(options.threshold ?? 2);
  if (!Number.isInteger(threshold) || threshold < 2) {
    throw new Error("AUTO_FAILOVER_FAILURE_THRESHOLD must be an integer >= 2.");
  }
  const strictWarn = Boolean(options.strictWarn);
  const normalizedSamples = samples.map((sample) => normalizeTruthTableSample(sample));
  if (normalizedSamples.length === 0) {
    return blockedManualReview({
      reason: "No truth-table evidence samples were provided.",
      threshold,
      strictWarn,
      samples: normalizedSamples,
    });
  }

  const regionEvaluations = Object.fromEntries(
    Object.entries(REGION_RULES).map(([region, rule]) => [
      region,
      evaluateRegionSamples(region, rule, normalizedSamples, { strictWarn }),
    ]),
  );

  const thresholdRegions = Object.entries(regionEvaluations)
    .filter(([, evaluation]) => evaluation.consecutiveFailures >= threshold)
    .map(([region]) => region);

  const latestFailures = Object.entries(regionEvaluations)
    .flatMap(([region, evaluation]) => evaluation.samples.at(-1)?.failedChecks.map((row) => ({ region, ...row })) || []);

  if (thresholdRegions.length === 0) {
    const transientRegions = Object.entries(regionEvaluations)
      .filter(([, evaluation]) => evaluation.consecutiveFailures > 0)
      .map(([region, evaluation]) => `${region}:${evaluation.consecutiveFailures}/${threshold}`);
    return {
      decisionStatus: "NOOP",
      selectedOperation: "",
      reason:
        transientRegions.length > 0
          ? `No region met the consecutive failure threshold; transient failures observed: ${transientRegions.join(", ")}.`
          : "No failover recommendation; all regional health samples are passing or WARN-only rows are ignored.",
      threshold,
      strictWarn,
      failedChecks: latestFailures,
      regionEvaluations,
    };
  }

  if (thresholdRegions.includes("default")) {
    return blockedManualReview({
      reason: "Default/global Mumbai health failed at threshold; default/global failover is manual-only and needs an explicit business decision.",
      threshold,
      strictWarn,
      samples: normalizedSamples,
      failedChecks: latestFailures,
      regionEvaluations,
    });
  }

  if (thresholdRegions.length > 1) {
    return blockedManualReview({
      reason: `Multiple regions met the failure threshold (${thresholdRegions.join(", ")}); automatic dry-run selection is blocked for manual review.`,
      threshold,
      strictWarn,
      samples: normalizedSamples,
      failedChecks: latestFailures,
      regionEvaluations,
    });
  }

  const region = thresholdRegions[0];
  return {
    decisionStatus: "RECOMMEND_FAILOVER",
    selectedOperation: REGION_RULES[region].operation,
    reason: `${REGION_RULES[region].label} failed ${threshold} consecutive health sample(s); recommend plan-only ${REGION_RULES[region].operation}.`,
    threshold,
    strictWarn,
    failedChecks: latestFailures.filter((row) => row.region === region),
    regionEvaluations,
  };
}

function blockedManualReview({ reason, threshold, strictWarn, failedChecks = [], regionEvaluations = {} }) {
  return {
    decisionStatus: "BLOCKED_MANUAL_REVIEW",
    selectedOperation: "",
    reason,
    threshold,
    strictWarn,
    failedChecks,
    regionEvaluations,
  };
}

function evaluateRegionSamples(region, rule, samples, { strictWarn }) {
  const evaluatedSamples = samples.map((sample) => {
    const rows = sample.rows.filter((row) => rule.matches(row) && isHealthRow(row));
    const failedChecks = rows.filter((row) => row.status === "FAIL" || (strictWarn && row.status === "WARN"));
    const warnChecks = rows.filter((row) => row.status === "WARN");
    return {
      generatedAt: sample.generatedAt,
      path: sample.path,
      status: failedChecks.length > 0 ? "FAIL" : "PASS",
      failedChecks,
      warnChecks,
    };
  });

  let consecutiveFailures = 0;
  for (let index = evaluatedSamples.length - 1; index >= 0; index -= 1) {
    if (evaluatedSamples[index].status !== "FAIL") break;
    consecutiveFailures += 1;
  }

  return {
    region,
    label: rule.label,
    operation: rule.operation,
    manualOnly: rule.manualOnly,
    consecutiveFailures,
    samples: evaluatedSamples,
  };
}

function isHealthRow(row) {
  const check = row.check || "";
  if (/^route53_/i.test(check)) return false;
  return /(_healthz|_ready|no_active_minio_ssh)$/i.test(check);
}
