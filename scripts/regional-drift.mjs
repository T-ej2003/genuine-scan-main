#!/usr/bin/env node

import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

import {
  buildReport,
  evaluateRegion,
  parseComposeServices,
  parseEnvBlock,
  renderMarkdownReport,
} from "./lib/regional-drift-core.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, "..");
const defaultConfigPath = path.join(repoRoot, "ops", "regional-drift.config.json");

const usage = `Usage: npm run ops:regional-drift -- [options]

Options:
  --config <path>        Regional drift config path. Default: ops/regional-drift.config.json
  --out-dir <path>       Write regional-drift-report.json and regional-drift-report.md.
  --json <path>          Write machine-readable JSON report to this path.
  --markdown <path>      Write Markdown report to this path.
  --no-aws              Skip AWS CLI inspection.
  --no-health           Skip HTTP ready health inspection.
  --ssh                 Inspect backend container env and docker compose service state over EC2 Instance Connect + SSH.
  --timeout-ms <ms>      HTTP health timeout. Default: 8000.
  --no-fail             Print findings but exit 0 even when FAIL findings exist.
  --help                Show this help.
`;

const parseArgs = (argv) => {
  const options = {
    configPath: defaultConfigPath,
    outDir: "",
    jsonPath: "",
    markdownPath: "",
    aws: true,
    health: true,
    ssh: false,
    timeoutMs: 8000,
    failOnDrift: true,
  };

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    const nextValue = () => {
      const value = argv[index + 1];
      if (!value || value.startsWith("--")) throw new Error(`Missing value for ${arg}`);
      index += 1;
      return value;
    };

    if (arg === "--config") options.configPath = path.resolve(process.cwd(), nextValue());
    else if (arg === "--out-dir") options.outDir = path.resolve(process.cwd(), nextValue());
    else if (arg === "--json") options.jsonPath = path.resolve(process.cwd(), nextValue());
    else if (arg === "--markdown") options.markdownPath = path.resolve(process.cwd(), nextValue());
    else if (arg === "--no-aws") options.aws = false;
    else if (arg === "--no-health") options.health = false;
    else if (arg === "--ssh") options.ssh = true;
    else if (arg === "--timeout-ms") options.timeoutMs = Number(nextValue());
    else if (arg === "--no-fail") options.failOnDrift = false;
    else if (arg === "--help" || arg === "-h") {
      console.log(usage);
      process.exit(0);
    } else {
      throw new Error(`Unknown option: ${arg}\n${usage}`);
    }
  }

  if (!Number.isFinite(options.timeoutMs) || options.timeoutMs <= 0) {
    throw new Error("--timeout-ms must be a positive number.");
  }

  if (options.outDir) {
    options.jsonPath ||= path.join(options.outDir, "regional-drift-report.json");
    options.markdownPath ||= path.join(options.outDir, "regional-drift-report.md");
  }

  return options;
};

const loadConfig = (configPath) => {
  if (!existsSync(configPath)) throw new Error(`Regional drift config not found: ${configPath}`);
  const config = JSON.parse(readFileSync(configPath, "utf8"));
  if (!Array.isArray(config.regions) || config.regions.length === 0) {
    throw new Error("Regional drift config must include a non-empty regions array.");
  }
  return config;
};

const runCommand = (command, args, options = {}) => {
  try {
    const stdout = execFileSync(command, args, {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      timeout: options.timeout || 20000,
      ...options.execOptions,
    });
    return { ok: true, stdout };
  } catch (error) {
    return {
      ok: false,
      stdout: error.stdout ? String(error.stdout) : "",
      stderr: error.stderr ? String(error.stderr) : "",
      error: error.message || String(error),
    };
  }
};

const runAwsJson = (region, args) => {
  const result = runCommand("aws", [...args, "--region", region, "--output", "json"], { timeout: 30000 });
  if (!result.ok) return { ok: false, error: result.stderr || result.error };
  try {
    return { ok: true, data: JSON.parse(result.stdout || "{}") };
  } catch (error) {
    return { ok: false, error: `AWS CLI returned invalid JSON: ${error.message || String(error)}` };
  }
};

const fetchHealth = async (url, timeoutMs) => {
  if (!url) {
    return {
      url,
      status: 0,
      contentType: "",
      body: "",
      error: new Error("No ready health URL configured."),
    };
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, {
      headers: { Accept: "application/json" },
      signal: controller.signal,
    });
    return {
      url,
      status: response.status,
      contentType: response.headers.get("content-type") || "",
      body: await response.text(),
    };
  } catch (error) {
    return {
      url,
      status: 0,
      contentType: "",
      body: "",
      error,
    };
  } finally {
    clearTimeout(timeout);
  }
};

const inspectAws = (regionConfig, snapshotFreshnessHours) => {
  const awsRegion = regionConfig.awsRegion;
  const inspection = {
    inspected: true,
    snapshotFreshnessHours,
    alarmNames: [],
    snapshots: [],
    s3HeadBucketOk: false,
  };

  const ec2Result = runAwsJson(awsRegion, ["ec2", "describe-instances", "--instance-ids", regionConfig.ec2.instanceId]);
  if (!ec2Result.ok) return { inspected: true, error: `EC2 inspection failed: ${ec2Result.error}` };
  const instance = ec2Result.data?.Reservations?.flatMap((reservation) => reservation.Instances || [])[0];
  inspection.ec2 = {
    instanceId: instance?.InstanceId || null,
    state: instance?.State?.Name || null,
    publicIpAddress: instance?.PublicIpAddress || null,
    privateIpAddress: instance?.PrivateIpAddress || null,
    availabilityZone: instance?.Placement?.AvailabilityZone || null,
    iamInstanceProfileArn: instance?.IamInstanceProfile?.Arn || null,
  };

  const rdsResult = runAwsJson(awsRegion, [
    "rds",
    "describe-db-instances",
    "--db-instance-identifier",
    regionConfig.database.instanceIdentifier,
  ]);
  if (!rdsResult.ok) return { inspected: true, error: `RDS inspection failed: ${rdsResult.error}` };
  const db = rdsResult.data?.DBInstances?.[0];
  inspection.rds = {
    identifier: db?.DBInstanceIdentifier || null,
    status: db?.DBInstanceStatus || null,
    endpoint: db?.Endpoint?.Address || null,
    engine: db?.Engine || null,
  };

  const alarmResult = runAwsJson(awsRegion, ["cloudwatch", "describe-alarms"]);
  if (!alarmResult.ok) return { inspected: true, error: `CloudWatch alarm inspection failed: ${alarmResult.error}` };
  inspection.alarmNames = (alarmResult.data?.MetricAlarms || []).map((alarm) => alarm.AlarmName).filter(Boolean);

  const snapshotResult = runAwsJson(awsRegion, [
    "rds",
    "describe-db-snapshots",
    "--db-instance-identifier",
    regionConfig.snapshots.dbInstanceIdentifier,
    "--snapshot-type",
    "manual",
  ]);
  if (!snapshotResult.ok) return { inspected: true, error: `RDS snapshot inspection failed: ${snapshotResult.error}` };
  inspection.snapshots = (snapshotResult.data?.DBSnapshots || []).map((snapshot) => ({
    id: snapshot.DBSnapshotIdentifier,
    createdAt: snapshot.SnapshotCreateTime,
    status: snapshot.Status,
  }));

  const bucketResult = runCommand("aws", ["s3api", "head-bucket", "--bucket", regionConfig.objectStorage.bucket, "--region", awsRegion], {
    timeout: 30000,
  });
  inspection.s3HeadBucketOk = bucketResult.ok;
  inspection.s3HeadBucketError = bucketResult.ok ? "" : bucketResult.stderr || bucketResult.error;

  return inspection;
};

const shellQuote = (value) => `'${String(value).replace(/'/g, "'\"'\"'")}'`;

const remotePathExpression = (value) => {
  const normalized = String(value || "").trim();
  if (normalized === "~") return "$HOME";
  if (normalized.startsWith("~/")) return `$HOME/${shellQuote(normalized.slice(2))}`;
  return shellQuote(normalized);
};

const inspectRuntimeViaSsh = (regionConfig, awsInspection) => {
  const instanceId = regionConfig.ec2.instanceId;
  const availabilityZone = awsInspection?.ec2?.availabilityZone;
  const publicIp = awsInspection?.ec2?.publicIpAddress;
  const sshUser = regionConfig.runtime?.sshUser || "ubuntu";
  const repoPath = regionConfig.runtime?.repoPath || "~/genuine-scan-main";
  const publicKeyPath = process.env.MSCQR_REGIONAL_DRIFT_SSH_PUBLIC_KEY || path.join(homedir(), ".ssh", "id_ed25519.pub");

  if (!instanceId || !availabilityZone || !publicIp) {
    return { inspected: true, error: "Missing EC2 instance ID, availability zone, or public IP for SSH inspection." };
  }

  if (!existsSync(publicKeyPath)) {
    return { inspected: true, error: `SSH public key not found: ${publicKeyPath}` };
  }

  const sendKey = runCommand(
    "aws",
    [
      "ec2-instance-connect",
      "send-ssh-public-key",
      "--instance-id",
      instanceId,
      "--availability-zone",
      availabilityZone,
      "--instance-os-user",
      sshUser,
      "--ssh-public-key",
      `file://${publicKeyPath}`,
      "--region",
      regionConfig.awsRegion,
    ],
    { timeout: 20000 }
  );
  if (!sendKey.ok) return { inspected: true, error: `EC2 Instance Connect failed: ${sendKey.stderr || sendKey.error}` };

  const remoteCommand = [
    `cd ${remotePathExpression(repoPath)}`,
    "echo __MSCQR_ENV_START__",
    "docker compose exec -T backend sh -lc 'env | sort | grep -E \"^(AWS_REGION=|OBJECT_STORAGE_|SUPER_ADMIN_BOOTSTRAP_ENABLED=|SUPER_ADMIN_BOOTSTRAP_AUTO_VERIFY=)\"' || true",
    "echo __MSCQR_ENV_END__",
    "echo __MSCQR_PS_START__",
    "docker compose ps --format json || docker compose ps",
    "echo __MSCQR_PS_END__",
  ].join(" && ");

  const sshResult = runCommand(
    "ssh",
    [
      "-o",
      "BatchMode=yes",
      "-o",
      "ConnectTimeout=10",
      "-o",
      "StrictHostKeyChecking=accept-new",
      `${sshUser}@${publicIp}`,
      remoteCommand,
    ],
    { timeout: 30000 }
  );

  if (!sshResult.ok) return { inspected: true, error: `SSH runtime command failed: ${sshResult.stderr || sshResult.error}` };

  const envMatch = sshResult.stdout.match(/__MSCQR_ENV_START__\n([\s\S]*?)\n__MSCQR_ENV_END__/);
  const psMatch = sshResult.stdout.match(/__MSCQR_PS_START__\n([\s\S]*?)\n__MSCQR_PS_END__/);

  return {
    inspected: true,
    env: parseEnvBlock(envMatch?.[1] || ""),
    services: parseComposeServices(psMatch?.[1] || ""),
  };
};

const skippedHealth = (regionConfig) => ({
  skipped: true,
  url: regionConfig.health?.readyUrl,
  status: 0,
  contentType: "application/json",
  payload: null,
});

const main = async () => {
  const options = parseArgs(process.argv.slice(2));
  const config = loadConfig(options.configPath);
  const now = new Date();
  const regionResults = [];

  for (const region of config.regions) {
    console.log(`Inspecting ${region.label} (${region.awsRegion})...`);
    const health = options.health ? await fetchHealth(region.health?.readyUrl, options.timeoutMs) : skippedHealth(region);
    const aws = options.aws ? inspectAws(region, config.snapshotFreshnessHours || 168) : { inspected: false };
    const runtime = options.ssh ? inspectRuntimeViaSsh(region, aws) : { inspected: false };

    regionResults.push(
      evaluateRegion({
        region,
        health,
        aws,
        runtime,
        now,
        snapshotFreshnessHours: config.snapshotFreshnessHours || 168,
      })
    );
  }

  const report = buildReport({
    config,
    regions: regionResults,
    generatedAt: now.toISOString(),
  });
  const markdown = renderMarkdownReport(report);

  if (options.jsonPath || options.markdownPath) {
    for (const target of [options.jsonPath, options.markdownPath].filter(Boolean)) {
      mkdirSync(path.dirname(target), { recursive: true });
    }
  }

  if (options.jsonPath) writeFileSync(options.jsonPath, `${JSON.stringify(report, null, 2)}\n`);
  if (options.markdownPath) writeFileSync(options.markdownPath, markdown);

  console.log(markdown);
  if (options.jsonPath) console.log(`Wrote JSON report: ${options.jsonPath}`);
  if (options.markdownPath) console.log(`Wrote Markdown report: ${options.markdownPath}`);

  if (options.failOnDrift && report.summary.status === "FAIL") {
    process.exitCode = 1;
  }
};

main().catch((error) => {
  console.error(`Regional drift check failed: ${error.message || String(error)}`);
  process.exit(1);
});
