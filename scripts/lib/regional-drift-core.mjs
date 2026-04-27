const STATUS_RANK = {
  PASS: 0,
  WARN: 1,
  FAIL: 2,
};

const SENSITIVE_KEY_PATTERN = /(password|secret|token|private|credential|connection|database_url|db_url|jwt|signing|smtp|access_key|secret_key)/i;
const SAFE_EMPTY_VALUE = "<empty>";

export const normalizeBlank = (value) => {
  if (value === undefined || value === null) return "";
  return String(value).trim();
};

export const isBlank = (value) => normalizeBlank(value) === "";

export const normalizeBool = (value, fallback = false) => {
  const normalized = normalizeBlank(value).toLowerCase();
  if (["1", "true", "yes", "on"].includes(normalized)) return true;
  if (["0", "false", "no", "off"].includes(normalized)) return false;
  return fallback;
};

export const redactValue = (key, value) => {
  if (value === undefined || value === null || value === "") return value;
  if (SENSITIVE_KEY_PATTERN.test(String(key))) return "<redacted>";
  if (typeof value === "string" && /(postgres(?:ql)?:\/\/|mongodb:\/\/|redis:\/\/)/i.test(value)) return "<redacted-url>";
  return value;
};

export const redactDeep = (input) => {
  if (Array.isArray(input)) return input.map((item) => redactDeep(item));
  if (typeof input === "string") return redactValue("", input);
  if (!input || typeof input !== "object") return input;

  return Object.fromEntries(
    Object.entries(input).map(([key, value]) => {
      if (SENSITIVE_KEY_PATTERN.test(key)) return [key, redactValue(key, value)];
      return [key, redactDeep(value)];
    })
  );
};

export const previewText = (value, length = 180) =>
  normalizeBlank(value)
    .replace(/\s+/g, " ")
    .slice(0, length);

export const finding = (status, check, message, remediation, evidence = {}) => ({
  status,
  check,
  message,
  remediation,
  evidence: redactDeep(evidence),
});

export const worstStatus = (items) =>
  items.reduce((current, item) => (STATUS_RANK[item.status] > STATUS_RANK[current] ? item.status : current), "PASS");

export const parseJsonHealthResponse = ({ url, status, contentType, body, error }) => {
  if (error) {
    return {
      ok: false,
      payload: null,
      finding: finding(
        "FAIL",
        "app_health",
        `Ready health request failed for ${url}.`,
        "Confirm the regional app is reachable and API routes are not blocked by security group, nginx, or backend availability.",
        { url, error: error.message || String(error) }
      ),
    };
  }

  const preview = previewText(body);
  const loweredContentType = normalizeBlank(contentType).toLowerCase();
  const loweredPreview = preview.toLowerCase();
  const looksHtml =
    loweredContentType.includes("text/html") ||
    loweredPreview.startsWith("<!doctype html") ||
    loweredPreview.startsWith("<html");

  if (looksHtml) {
    return {
      ok: false,
      payload: null,
      finding: finding(
        "FAIL",
        "app_health",
        `Ready health expected JSON but received HTML for ${url}.`,
        "Fix the API routing/proxy order so /api/health/ready reaches the backend instead of the frontend SPA fallback.",
        { url, status, contentType, preview }
      ),
    };
  }

  let payload = null;
  try {
    payload = body ? JSON.parse(body) : null;
  } catch (parseError) {
    return {
      ok: false,
      payload: null,
      finding: finding(
        "FAIL",
        "app_health",
        `Ready health response was not valid JSON for ${url}.`,
        "Return stable JSON from the backend health endpoint and keep nginx/frontend fallbacks away from API routes.",
        { url, status, contentType, preview, parseError: parseError.message || String(parseError) }
      ),
    };
  }

  if (!status || status < 200 || status >= 300) {
    return {
      ok: false,
      payload,
      finding: finding(
        "FAIL",
        "app_health",
        `Ready health returned HTTP ${status} for ${url}.`,
        "Inspect backend dependency readiness before considering this region eligible for traffic.",
        { url, status, contentType, payload }
      ),
    };
  }

  return {
    ok: true,
    payload,
    finding: finding("PASS", "app_health", `Ready health returned JSON successfully for ${url}.`, "No action required.", {
      url,
      status,
      contentType,
    }),
  };
};

export const extractObjectStorageHealth = (payload) => {
  const objectStorage = payload?.dependencies?.objectStorage || payload?.objectStorage || null;
  if (!objectStorage || typeof objectStorage !== "object") return null;
  return {
    configured: objectStorage.configured,
    ready: objectStorage.ready,
    bucket: objectStorage.bucket ?? null,
    region: objectStorage.region ?? null,
    endpoint: objectStorage.endpoint ?? null,
    mode: objectStorage.mode ?? null,
    reason: objectStorage.reason ?? null,
  };
};

export const evaluateHealthDependencies = (payload) => {
  const dependencies = payload?.dependencies;
  if (!dependencies || typeof dependencies !== "object") {
    return [
      finding(
        "FAIL",
        "health_dependencies",
        "Ready health payload does not include dependency status.",
        "Ensure /health/ready returns dependencies.database, dependencies.redis, and dependencies.objectStorage.",
        { payload }
      ),
    ];
  }

  return Object.entries(dependencies).map(([name, dependency]) => {
    const configured = dependency?.configured !== false;
    const ready = dependency?.ready === true || configured === false;
    if (ready) {
      return finding("PASS", `dependency_${name}`, `${name} dependency is ready or intentionally unconfigured.`, "No action required.", {
        configured,
        ready: dependency?.ready,
      });
    }

    return finding(
      "FAIL",
      `dependency_${name}`,
      `${name} dependency is not ready.`,
      "Inspect the dependency, regional networking, credentials mode, and service logs before failover.",
      { configured, ready: dependency?.ready, reason: dependency?.reason || dependency?.error }
    );
  });
};

export const evaluateObjectStorage = (expected, actual) => {
  if (!actual) {
    return [
      finding(
        "FAIL",
        "object_storage_health",
        "Ready health does not expose object storage status.",
        "Expose object storage readiness in /health/ready before using this region for production traffic.",
        { expected }
      ),
    ];
  }

  const checks = [];
  const expectedEndpoint = expected.endpoint ?? null;
  const actualEndpoint = isBlank(actual.endpoint) ? null : actual.endpoint;

  checks.push(
    actual.ready === true && actual.configured !== false
      ? finding("PASS", "object_storage_ready", "Object storage reports ready.", "No action required.", actual)
      : finding(
          "FAIL",
          "object_storage_ready",
          "Object storage is not ready.",
          "Fix IAM role, bucket permissions, region, or backend object storage configuration before traffic cutover.",
          actual
        )
  );

  checks.push(
    actual.bucket === expected.bucket
      ? finding("PASS", "object_storage_bucket", "Object storage bucket matches the regional bucket.", "No action required.", {
          bucket: actual.bucket,
        })
      : finding(
          "FAIL",
          "object_storage_bucket",
          `Object storage bucket drifted from ${expected.bucket}.`,
          "Set OBJECT_STORAGE_BUCKET to the region-local production artifacts bucket.",
          { expected: expected.bucket, actual: actual.bucket }
        )
  );

  checks.push(
    actual.region === expected.region
      ? finding("PASS", "object_storage_region", "Object storage region matches the deployment region.", "No action required.", {
          region: actual.region,
        })
      : finding(
          "FAIL",
          "object_storage_region",
          `Object storage region drifted from ${expected.region}.`,
          "Set OBJECT_STORAGE_REGION/AWS_REGION to the deployment region and recreate backend/worker containers.",
          { expected: expected.region, actual: actual.region }
        )
  );

  checks.push(
    actualEndpoint === expectedEndpoint
      ? finding("PASS", "object_storage_endpoint", "Object storage endpoint is blank for native S3.", "No action required.", {
          endpoint: actualEndpoint,
        })
      : finding(
          "FAIL",
          "object_storage_endpoint",
          "Object storage endpoint is not blank; this indicates MinIO/custom S3 mode drift.",
          "Clear OBJECT_STORAGE_ENDPOINT and use EC2 IAM-role-native S3 credentials.",
          { expected: expectedEndpoint, actual: actual.endpoint }
        )
  );

  checks.push(
    actual.mode === expected.mode
      ? finding("PASS", "object_storage_mode", "Object storage credential mode matches IAM/default credentials.", "No action required.", {
          mode: actual.mode,
        })
      : finding(
          "FAIL",
          "object_storage_mode",
          `Object storage mode drifted from ${expected.mode}.`,
          "Remove static object storage access keys and rely on the EC2 instance role.",
          { expected: expected.mode, actual: actual.mode }
        )
  );

  return checks;
};

export const evaluateRuntimeEnvironment = (region, runtime) => {
  if (!runtime?.inspected) {
    return [
      finding(
        "WARN",
        "runtime_environment",
        "Backend container runtime was not inspected.",
        "Run the checker with --ssh from an operator workstation that can use EC2 Instance Connect to verify container env and MinIO process state.",
        { ssh: false }
      ),
    ];
  }

  if (runtime.error) {
    return [
      finding(
        "WARN",
        "runtime_environment",
        "Backend container runtime inspection failed.",
        "Confirm EC2 Instance Connect, SSH key, security group, and docker compose access, then rerun with --ssh.",
        { error: runtime.error }
      ),
    ];
  }

  const env = runtime.env || {};
  const checks = [];
  const objectStorageEndpoint = normalizeBlank(env.OBJECT_STORAGE_ENDPOINT);
  const accessKey = normalizeBlank(env.OBJECT_STORAGE_ACCESS_KEY);
  const secretKey = normalizeBlank(env.OBJECT_STORAGE_SECRET_KEY);
  const forcePathStyle = normalizeBool(env.OBJECT_STORAGE_FORCE_PATH_STYLE, false);

  checks.push(
    env.AWS_REGION === region.runtime.awsRegion
      ? finding("PASS", "runtime_aws_region", "Backend AWS_REGION matches regional expectation.", "No action required.", {
          AWS_REGION: env.AWS_REGION,
        })
      : finding(
          "FAIL",
          "runtime_aws_region",
          "Backend AWS_REGION does not match the deployment region.",
          "Update region-local env and recreate backend/worker containers.",
          { expected: region.runtime.awsRegion, actual: env.AWS_REGION }
        )
  );

  checks.push(
    objectStorageEndpoint === ""
      ? finding("PASS", "runtime_object_storage_endpoint", "Runtime OBJECT_STORAGE_ENDPOINT is blank.", "No action required.", {
          OBJECT_STORAGE_ENDPOINT: SAFE_EMPTY_VALUE,
        })
      : finding(
          "FAIL",
          "runtime_object_storage_endpoint",
          "Runtime OBJECT_STORAGE_ENDPOINT is set, which is not steady-state S3 IAM mode.",
          "Clear OBJECT_STORAGE_ENDPOINT and recreate backend/worker containers.",
          { OBJECT_STORAGE_ENDPOINT: objectStorageEndpoint }
        )
  );

  checks.push(
    accessKey === "" && secretKey === ""
      ? finding("PASS", "runtime_object_storage_static_keys", "Runtime object storage static keys are blank.", "No action required.", {
          OBJECT_STORAGE_ACCESS_KEY: SAFE_EMPTY_VALUE,
          OBJECT_STORAGE_SECRET_KEY: SAFE_EMPTY_VALUE,
        })
      : finding(
          "FAIL",
          "runtime_object_storage_static_keys",
          "Runtime object storage static keys are present.",
          "Remove OBJECT_STORAGE_ACCESS_KEY/OBJECT_STORAGE_SECRET_KEY from production env and rely on EC2 IAM role credentials.",
          { OBJECT_STORAGE_ACCESS_KEY: accessKey ? "<set>" : SAFE_EMPTY_VALUE, OBJECT_STORAGE_SECRET_KEY: secretKey ? "<set>" : SAFE_EMPTY_VALUE }
        )
  );

  checks.push(
    forcePathStyle === false
      ? finding("PASS", "runtime_object_storage_path_style", "Runtime path-style object storage is disabled.", "No action required.", {
          OBJECT_STORAGE_FORCE_PATH_STYLE: env.OBJECT_STORAGE_FORCE_PATH_STYLE || SAFE_EMPTY_VALUE,
        })
      : finding(
          "FAIL",
          "runtime_object_storage_path_style",
          "Runtime OBJECT_STORAGE_FORCE_PATH_STYLE is enabled.",
          "Set OBJECT_STORAGE_FORCE_PATH_STYLE=false for native S3 and recreate backend/worker containers.",
          { OBJECT_STORAGE_FORCE_PATH_STYLE: env.OBJECT_STORAGE_FORCE_PATH_STYLE }
        )
  );

  const bootstrapEnabled = normalizeBool(env.SUPER_ADMIN_BOOTSTRAP_ENABLED, false);
  checks.push(
    bootstrapEnabled === Boolean(region.environment?.superAdminBootstrapEnabled)
      ? finding("PASS", "super_admin_bootstrap", "Super-admin bootstrap steady-state posture matches expectation.", "No action required.", {
          SUPER_ADMIN_BOOTSTRAP_ENABLED: String(bootstrapEnabled),
        })
      : finding(
          "FAIL",
          "super_admin_bootstrap",
          "Super-admin bootstrap is not in steady-state posture.",
          "Disable bootstrap after first-login recovery and remove bootstrap password from production env.",
          { expected: region.environment?.superAdminBootstrapEnabled, actual: bootstrapEnabled }
        )
  );

  const minioRunning = runtime.services?.some((service) => /minio/i.test(service.name || service.service || "") && /running|up/i.test(service.state || service.status || ""));
  checks.push(
    minioRunning
      ? finding(
          "WARN",
          "minio_runtime",
          "MinIO service is still running on this host.",
          "Keep MinIO only as rollback residue until the planned cleanup; do not route production object storage through it.",
          { minioRunning: true }
        )
      : finding("PASS", "minio_runtime", "MinIO is not running in the inspected docker compose services.", "No action required.", {
          minioRunning: false,
        })
  );

  return checks;
};

export const evaluateAlarmPresence = (expectedNames, actualNames) => {
  const actual = new Set(actualNames || []);
  const missing = expectedNames.filter((name) => !actual.has(name));
  if (missing.length === 0) {
    return [
      finding("PASS", "cloudwatch_alarms", "Expected CloudWatch alarms are present.", "No action required.", {
        expectedCount: expectedNames.length,
      }),
    ];
  }

  return [
    finding(
      "FAIL",
      "cloudwatch_alarms",
      `${missing.length} expected CloudWatch alarm(s) are missing.`,
      "Create or restore the missing alarms before considering the region operationally ready.",
      { missing, expectedCount: expectedNames.length }
    ),
  ];
};

export const evaluateSnapshotFreshness = ({ snapshots, prefix, maxAgeHours, now = new Date() }) => {
  const matching = (snapshots || [])
    .filter((snapshot) => !prefix || String(snapshot.id || snapshot.DBSnapshotIdentifier || "").startsWith(prefix))
    .map((snapshot) => ({
      id: snapshot.id || snapshot.DBSnapshotIdentifier,
      createdAt: snapshot.createdAt || snapshot.SnapshotCreateTime,
      status: snapshot.status || snapshot.Status,
    }))
    .filter((snapshot) => snapshot.id && snapshot.createdAt)
    .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());

  if (matching.length === 0) {
    return [
      finding(
        "FAIL",
        "manual_snapshot",
        "No matching manual RDS snapshot was found.",
        "Take a manual region-local DB snapshot and rerun the drift checker.",
        { prefix }
      ),
    ];
  }

  const latest = matching[0];
  const ageHours = Math.max(0, (now.getTime() - new Date(latest.createdAt).getTime()) / 36e5);
  if (ageHours <= maxAgeHours) {
    return [
      finding("PASS", "manual_snapshot", "Latest manual RDS snapshot is fresh enough.", "No action required.", {
        snapshot: latest.id,
        createdAt: latest.createdAt,
        ageHours: Number(ageHours.toFixed(1)),
        maxAgeHours,
      }),
    ];
  }

  return [
    finding(
      "WARN",
      "manual_snapshot",
      "Latest manual RDS snapshot is older than the configured freshness window.",
      "Take a fresh manual snapshot before planned maintenance or failover readiness sign-off.",
      { snapshot: latest.id, createdAt: latest.createdAt, ageHours: Number(ageHours.toFixed(1)), maxAgeHours }
    ),
  ];
};

export const evaluateAwsInspection = (region, aws, now = new Date()) => {
  if (!aws?.inspected) {
    return [
      finding(
        "WARN",
        "aws_inspection",
        "AWS resource inspection was skipped.",
        "Run without --no-aws from a workstation with AWS CLI access to verify EC2, RDS, S3, alarms, and snapshots.",
        { aws: false }
      ),
    ];
  }

  if (aws.error) {
    return [
      finding(
        "FAIL",
        "aws_inspection",
        "AWS resource inspection failed.",
        "Check AWS credentials, region access, and IAM permissions for read-only EC2/RDS/S3/CloudWatch inspection.",
        { error: aws.error }
      ),
    ];
  }

  const checks = [];
  checks.push(
    aws.s3HeadBucketOk
      ? finding("PASS", "s3_bucket", "Regional S3 bucket exists and is accessible.", "No action required.", {
          bucket: region.objectStorage.bucket,
        })
      : finding(
          "FAIL",
          "s3_bucket",
          "Regional S3 bucket was not accessible through AWS inspection.",
          "Confirm bucket existence, region, and IAM permissions for the operator identity.",
          { bucket: region.objectStorage.bucket, error: aws.s3HeadBucketError }
        )
  );

  const rdsEndpoint = aws.rds?.endpoint || "";
  checks.push(
    rdsEndpoint.includes(region.database.endpointRegionToken)
      ? finding("PASS", "rds_endpoint_region", "RDS endpoint is aligned to the expected region.", "No action required.", {
          endpointHost: rdsEndpoint,
        })
      : finding(
          "FAIL",
          "rds_endpoint_region",
          "RDS endpoint does not appear aligned to the expected region.",
          "Confirm the standby app is not pointing at the active-region database.",
          { expectedToken: region.database.endpointRegionToken, endpointHost: rdsEndpoint || null }
        )
  );

  checks.push(
    aws.ec2?.instanceId === region.ec2.instanceId
      ? finding("PASS", "ec2_instance", "Expected EC2 instance was found.", "No action required.", {
          instanceId: aws.ec2.instanceId,
          state: aws.ec2.state,
          publicIpAddress: aws.ec2.publicIpAddress || null,
        })
      : finding(
          "FAIL",
          "ec2_instance",
          "Expected EC2 instance was not found.",
          "Confirm the regional instance ID in ops/regional-drift.config.json or restore the EC2 host.",
          { expected: region.ec2.instanceId, actual: aws.ec2?.instanceId || null }
        )
  );

  checks.push(...evaluateAlarmPresence(region.alarms || [], aws.alarmNames || []));
  checks.push(
    ...evaluateSnapshotFreshness({
      snapshots: aws.snapshots || [],
      prefix: region.snapshots?.manualSnapshotPrefix,
      maxAgeHours: region.snapshotFreshnessHours || aws.snapshotFreshnessHours || 168,
      now,
    })
  );

  return checks;
};

export const evaluateRegion = ({ region, health, aws, runtime, now = new Date(), snapshotFreshnessHours = 168 }) => {
  const findings = [];
  const healthParsed = health?.skipped
    ? {
        payload: health.payload,
        finding: finding(
          "WARN",
          "app_health",
          "Ready health inspection was skipped.",
          "Run without --no-health before considering a region eligible for traffic.",
          { url: health.url }
        ),
      }
    : parseJsonHealthResponse(health || {});
  findings.push(healthParsed.finding);

  if (healthParsed.payload) {
    findings.push(...evaluateHealthDependencies(healthParsed.payload));
    findings.push(...evaluateObjectStorage(region.objectStorage, extractObjectStorageHealth(healthParsed.payload)));
  }

  findings.push(
    finding(
      "PASS",
      "region_role",
      `${region.label} is configured as ${region.role}.`,
      "No action required.",
      { role: region.role, awsRegion: region.awsRegion }
    )
  );

  findings.push(...evaluateAwsInspection({ ...region, snapshotFreshnessHours }, aws, now));
  findings.push(...evaluateRuntimeEnvironment(region, runtime));

  return {
    id: region.id,
    label: region.label,
    role: region.role,
    awsRegion: region.awsRegion,
    status: worstStatus(findings),
    findings,
  };
};

export const buildReport = ({ config, regions, generatedAt = new Date().toISOString() }) => {
  const summary = {
    status: worstStatus(regions),
    pass: regions.filter((region) => region.status === "PASS").length,
    warn: regions.filter((region) => region.status === "WARN").length,
    fail: regions.filter((region) => region.status === "FAIL").length,
    regions: regions.length,
  };

  return redactDeep({
    title: config.reportTitle || "MSCQR Regional Drift Audit",
    generatedAt,
    summary,
    regions,
  });
};

export const renderMarkdownReport = (report) => {
  const lines = [
    `# ${report.title}`,
    "",
    `Generated: ${report.generatedAt}`,
    "",
    `Overall status: **${report.summary.status}**`,
    "",
    `Regions: ${report.summary.regions} | PASS: ${report.summary.pass} | WARN: ${report.summary.warn} | FAIL: ${report.summary.fail}`,
    "",
    "## Region Findings",
    "",
  ];

  for (const region of report.regions) {
    lines.push(`### ${region.label} (${region.awsRegion})`);
    lines.push("");
    lines.push(`Role: \`${region.role}\``);
    lines.push("");
    lines.push(`Status: **${region.status}**`);
    lines.push("");
    lines.push("| Status | Check | Finding | Remediation |");
    lines.push("| --- | --- | --- | --- |");

    for (const item of region.findings) {
      lines.push(
        `| ${item.status} | \`${item.check}\` | ${String(item.message).replace(/\|/g, "\\|")} | ${String(item.remediation).replace(/\|/g, "\\|")} |`
      );
    }

    lines.push("");
  }

  lines.push("## Operator Notes");
  lines.push("");
  lines.push("- Reports are redacted for internal sharing; do not paste raw env files or full connection strings into incident channels.");
  lines.push("- A FAIL means the region should not receive production traffic until remediated or explicitly accepted by the incident commander.");
  lines.push("- A WARN is operational debt that should be cleared before planned failover, tabletop sign-off, or Phase 1B promotion.");
  lines.push("");

  return `${lines.join("\n")}\n`;
};

export const parseEnvBlock = (text) => {
  const env = {};
  for (const line of String(text || "").split(/\r?\n/)) {
    const separator = line.indexOf("=");
    if (separator <= 0) continue;
    const key = line.slice(0, separator).trim();
    const value = line.slice(separator + 1).trim();
    env[key] = value;
  }
  return env;
};

export const parseComposeServices = (text) => {
  const services = [];
  for (const line of String(text || "").split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      const parsed = JSON.parse(trimmed);
      services.push({
        name: parsed.Name || parsed.name || parsed.Service || parsed.service || "",
        service: parsed.Service || parsed.service || "",
        state: parsed.State || parsed.state || "",
        status: parsed.Status || parsed.status || "",
      });
    } catch {
      const parts = trimmed.split(/\s{2,}/);
      services.push({ name: parts[0] || trimmed, service: parts[0] || trimmed, state: trimmed, status: trimmed });
    }
  }
  return services;
};
