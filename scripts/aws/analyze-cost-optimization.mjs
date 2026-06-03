#!/usr/bin/env node

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import process from "node:process";
import { fileURLToPath, pathToFileURL } from "node:url";

export const ACTION_CATEGORIES = {
  KEEP: "KEEP",
  OBSERVE_ONLY: "OBSERVE_ONLY",
  REVIEW_REQUIRED: "REVIEW_REQUIRED",
  CANDIDATE_RIGHTSIZE_AFTER_METRICS: "CANDIDATE_RIGHTSIZE_AFTER_METRICS",
  CANDIDATE_STOP_AFTER_APPROVAL: "CANDIDATE_STOP_AFTER_APPROVAL",
  CANDIDATE_DELETE_AFTER_BACKUP_AND_APPROVAL: "CANDIDATE_DELETE_AFTER_BACKUP_AND_APPROVAL",
  NEVER_DELETE_WITHOUT_BACKUP: "NEVER_DELETE_WITHOUT_BACKUP",
  BLOCKED_UNTIL_MORE_EVIDENCE: "BLOCKED_UNTIL_MORE_EVIDENCE",
};

export const CLASSIFICATIONS = ACTION_CATEGORIES;

const DEFAULT_COST_EVIDENCE_DIR = "/Users/abhiramteja/Downloads/MSCQR-AWS-Cost-Optimization-20260603T114126Z";
const DEFAULT_DEEP_DIVE_EVIDENCE_DIR = "/Users/abhiramteja/Downloads/MSCQR-AWS-Cost-Deep-Dive-20260603T121634Z";
const DOWNLOADS_DIR = "/Users/abhiramteja/Downloads";
const DOWNLOAD_REPORT_ROOT = path.join(DOWNLOADS_DIR, "MSCQR-AWS-Cost-Optimization-Reports");
const DEFAULT_FORECAST_USD = 931.6012448831261;
const TARGET_CEILING_LOW_USD = 700;
const TARGET_CEILING_HIGH_USD = 730;
const REGIONS = ["ap-south-1", "af-south-1", "eu-west-2", "us-east-1"];

const SERVICE_ALIASES = new Map([
  ["Amazon Relational Database Service", "RDS"],
  ["Relational Database Service", "RDS"],
  ["RDS", "RDS"],
  ["Amazon ElastiCache", "ElastiCache"],
  ["ElastiCache", "ElastiCache"],
  ["Amazon Elastic Compute Cloud - Compute", "EC2 Compute"],
  ["EC2-Instances", "EC2 Compute"],
  ["EC2 Compute", "EC2 Compute"],
  ["EC2 - Other", "EC2 Other"],
  ["EC2-Other", "EC2 Other"],
  ["EC2 Other", "EC2 Other"],
  ["Amazon Elastic Load Balancing", "ELB"],
  ["Elastic Load Balancing", "ELB"],
  ["ELB", "ELB"],
  ["Amazon Virtual Private Cloud", "VPC"],
  ["VPC", "VPC"],
  ["AmazonCloudWatch", "CloudWatch"],
  ["CloudWatch", "CloudWatch"],
  ["AWS WAF", "WAF"],
  ["WAF", "WAF"],
  ["AWS Secrets Manager", "Secrets Manager"],
  ["Secrets Manager", "Secrets Manager"],
  ["Amazon Lightsail", "Lightsail"],
  ["Lightsail", "Lightsail"],
  ["Amazon Route 53", "Route 53"],
  ["Route 53", "Route 53"],
  ["Amazon Simple Storage Service", "S3"],
  ["S3", "S3"],
  ["Amazon EC2 Container Registry (ECR)", "ECR"],
  ["EC2 Container Registry (ECR)", "ECR"],
  ["Amazon Elastic Container Service", "ECS"],
  ["Elastic Container Service", "ECS"],
  ["Tax", "Tax"],
  ["Total costs", "Total costs"],
]);

const usage = `Usage:
  node scripts/aws/analyze-cost-optimization.mjs
  node scripts/aws/analyze-cost-optimization.mjs --evidence-dir <path> [--screenshots-dir <path>]
  node scripts/aws/analyze-cost-optimization.mjs --archive <path> [--screenshots-dir <path>]

This analyzer reads local evidence only and writes local reports.
No AWS mutation was performed.
`;

export function parseArgs(argv) {
  const options = {
    archive: "",
    downloadsRoot: DOWNLOAD_REPORT_ROOT,
    evidenceDir: "",
    outputRoot: "",
    screenshotsDir: "",
    timestamp: "",
  };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    const next = () => {
      const value = argv[index + 1];
      if (!value || value.startsWith("--")) throw new Error(`Missing value for ${arg}`);
      index += 1;
      return value;
    };
    if (arg === "--archive") options.archive = next();
    else if (arg === "--downloads-root") options.downloadsRoot = next();
    else if (arg === "--evidence-dir") options.evidenceDir = next();
    else if (arg === "--output-root") options.outputRoot = next();
    else if (arg === "--screenshots-dir") options.screenshotsDir = next();
    else if (arg === "--timestamp") options.timestamp = next();
    else if (arg === "-h" || arg === "--help") {
      console.log(usage);
      process.exit(0);
    } else {
      throw new Error(`Unknown option: ${arg}\n${usage}`);
    }
  }
  if (options.archive && options.evidenceDir) throw new Error("Use either --archive or --evidence-dir, not both.");
  return options;
}

function utcStamp() {
  return new Date().toISOString().replace(/[-:]/g, "").replace(/\.\d{3}Z$/u, "Z");
}

function readJson(filePath) {
  return JSON.parse(readFileSync(filePath, "utf8"));
}

function readJsonOptional(filePath, fallback = null) {
  if (!existsSync(filePath)) return fallback;
  return readJson(filePath);
}

function listFiles(root) {
  if (!root || !existsSync(root)) return [];
  return readdirSync(root, { withFileTypes: true }).flatMap((entry) => {
    const fullPath = path.join(root, entry.name);
    if (entry.isDirectory()) return listFiles(fullPath);
    return [fullPath];
  });
}

function extractArchive(archivePath) {
  const tempRoot = mkdtempSync(path.join(tmpdir(), "mscqr-cost-evidence-"));
  const tar = existsSync("/usr/bin/tar") ? "/usr/bin/tar" : "tar";
  execFileSync(tar, ["-xzf", archivePath, "-C", tempRoot], { stdio: ["ignore", "pipe", "pipe"] });
  const dirs = readdirSync(tempRoot)
    .map((name) => path.join(tempRoot, name))
    .filter((item) => statSync(item).isDirectory());
  if (dirs.length === 1) return dirs[0];
  return tempRoot;
}

function evidenceLooksUseful(dir) {
  if (!existsSync(dir)) return false;
  const files = listFiles(dir).map((file) => path.basename(file));
  return files.some((name) => /^1\d-cost-.*usage-type\.json$/u.test(name) || /^cost-.*by-service\.json$/u.test(name));
}

export function selectEvidence(options = {}, root = process.cwd()) {
  if (options.archive) {
    const archivePath = path.resolve(root, options.archive);
    if (!existsSync(archivePath)) throw new Error(`Archive not found: ${archivePath}`);
    return { evidenceDir: extractArchive(archivePath), sourcePath: archivePath, sourceType: "archive" };
  }
  if (options.evidenceDir) {
    const evidenceDir = path.resolve(root, options.evidenceDir);
    if (!existsSync(evidenceDir)) throw new Error(`Evidence directory not found: ${evidenceDir}`);
    return { evidenceDir, sourcePath: evidenceDir, sourceType: "directory" };
  }
  if (evidenceLooksUseful(DEFAULT_DEEP_DIVE_EVIDENCE_DIR)) {
    return { evidenceDir: DEFAULT_DEEP_DIVE_EVIDENCE_DIR, sourcePath: DEFAULT_DEEP_DIVE_EVIDENCE_DIR, sourceType: "directory" };
  }
  if (evidenceLooksUseful(DEFAULT_COST_EVIDENCE_DIR)) {
    return { evidenceDir: DEFAULT_COST_EVIDENCE_DIR, sourcePath: DEFAULT_COST_EVIDENCE_DIR, sourceType: "directory" };
  }
  const candidates = existsSync(DOWNLOADS_DIR)
    ? readdirSync(DOWNLOADS_DIR)
        .filter((name) => /^MSCQR-AWS-Cost-(Deep-Dive|Optimization)-/u.test(name))
        .map((name) => path.join(DOWNLOADS_DIR, name))
        .filter((item) => statSync(item).isDirectory())
        .sort()
        .reverse()
    : [];
  const selected = candidates.find(evidenceLooksUseful);
  if (selected) return { evidenceDir: selected, sourcePath: selected, sourceType: "directory" };
  throw new Error("No local cost evidence folder found.");
}

function parseCsvLine(line) {
  const values = [];
  let current = "";
  let quoted = false;
  for (let index = 0; index < line.length; index += 1) {
    const char = line[index];
    if (char === '"' && line[index + 1] === '"') {
      current += '"';
      index += 1;
    } else if (char === '"') {
      quoted = !quoted;
    } else if (char === "," && !quoted) {
      values.push(current);
      current = "";
    } else {
      current += char;
    }
  }
  values.push(current);
  return values.map((value) => value.replace(/^\uFEFF/u, ""));
}

function canonicalService(rawName) {
  return SERVICE_ALIASES.get(rawName) || rawName;
}

function parseCostCsv(filePath) {
  const lines = readFileSync(filePath, "utf8").split(/\r?\n/u).filter(Boolean);
  if (lines.length < 2) return null;
  const headers = parseCsvLine(lines[0]);
  const totalRow = lines.map(parseCsvLine).find((row) => row[0] === "Service total" || row[0] === "Usage type total");
  if (!totalRow) return null;
  const kind = headers[0] === "Usage type" ? "usage-type" : "service";
  const values = {};
  for (let index = 1; index < headers.length; index += 1) {
    const rawName = headers[index].replace(/\(\$\)$/u, "").trim();
    const name = kind === "service" ? canonicalService(rawName) : rawName;
    const amount = Number(totalRow[index] || 0);
    if (Number.isFinite(amount)) values[name] = amount;
  }
  return { filePath, kind, values, total: values["Total costs"] || 0 };
}

function numeric(value, fallback = 0) {
  const number = Number(value);
  return Number.isFinite(number) ? number : fallback;
}

function currency(value) {
  return `$${numeric(value).toFixed(2)}`;
}

function serviceCostFromJson(filePath) {
  const data = readJsonOptional(filePath);
  const services = {};
  for (const time of data?.ResultsByTime || []) {
    for (const group of time.Groups || []) {
      const rawName = group.Keys?.[0] || "Unknown";
      const service = canonicalService(rawName);
      const amount = numeric(group.Metrics?.UnblendedCost?.Amount ?? group.Metrics?.AmortizedCost?.Amount);
      services[service] = (services[service] || 0) + amount;
    }
  }
  return services;
}

export function parseUsageTypeCost(filePath) {
  const data = readJsonOptional(filePath, {});
  const usageTypes = {};
  let total = 0;
  for (const time of data.ResultsByTime || []) {
    for (const group of time.Groups || []) {
      const usageType = group.Keys?.[0] || "Unknown";
      const amount = numeric(group.Metrics?.UnblendedCost?.Amount ?? group.Metrics?.AmortizedCost?.Amount);
      const usageQuantity = numeric(group.Metrics?.UsageQuantity?.Amount);
      const unit = group.Metrics?.UsageQuantity?.Unit || "";
      if (!usageTypes[usageType]) usageTypes[usageType] = { usageType, amount: 0, usageQuantity: 0, unit };
      usageTypes[usageType].amount += amount;
      usageTypes[usageType].usageQuantity += usageQuantity;
      usageTypes[usageType].unit ||= unit;
      total += amount;
    }
  }
  return {
    filePath,
    total,
    usageTypes: Object.values(usageTypes).sort((a, b) => b.amount - a.amount),
  };
}

function mergeMax(...sets) {
  const merged = {};
  for (const values of sets) {
    for (const [key, amount] of Object.entries(values || {})) merged[key] = Math.max(merged[key] || 0, amount);
  }
  return merged;
}

function sumValues(values) {
  return Object.values(values || {}).reduce((sum, value) => sum + numeric(value), 0);
}

function costCsvFiles(evidenceDir, screenshotsDir = "") {
  const dirs = [evidenceDir, path.dirname(evidenceDir), screenshotsDir];
  if (path.resolve(evidenceDir).startsWith(path.resolve(DOWNLOADS_DIR))) dirs.push(DOWNLOADS_DIR);
  const seen = new Set();
  return dirs
    .flatMap((dir) => listFiles(dir))
    .filter((file) => /^costs(?: \(\d+\))?\.csv$/u.test(path.basename(file)))
    .filter((file) => {
      if (seen.has(file)) return false;
      seen.add(file);
      return true;
    });
}

function screenshotFiles(evidenceDir, screenshotsDir = "") {
  const dirs = [path.join(evidenceDir, "screenshots"), screenshotsDir].filter(Boolean);
  const seen = new Set();
  return dirs
    .flatMap((dir) => listFiles(dir))
    .filter((file) => /\.(png|jpg|jpeg)$/iu.test(file))
    .filter((file) => {
      if (seen.has(file)) return false;
      seen.add(file);
      return true;
    });
}

function regionFromFile(filePath) {
  const parts = filePath.split(path.sep);
  return parts.find((part) => REGIONS.includes(part)) || "";
}

function arrayFrom(data, keys = []) {
  if (!data) return [];
  if (Array.isArray(data)) return data;
  for (const key of keys) if (Array.isArray(data[key])) return data[key];
  const firstArray = Object.values(data).find(Array.isArray);
  return Array.isArray(firstArray) ? firstArray : [];
}

function findFilesByName(evidenceDir, names) {
  const nameSet = new Set(names);
  return listFiles(evidenceDir).filter((file) => nameSet.has(path.basename(file)));
}

function uniqueFiles(files) {
  return [...new Set(files)];
}

function readArrayFiles(files, keys = []) {
  return uniqueFiles(files).flatMap((file) => {
    const region = regionFromFile(file);
    return arrayFrom(readJsonOptional(file, []), keys).map((item) => ({ ...item, Region: item.Region || region || item.Region }));
  });
}

function tagValue(tags = [], key = "Name") {
  const tag = tags.find((item) => item.Key === key || item.key === key);
  return tag?.Value || tag?.value || "";
}

function instanceName(instance) {
  return instance.Name || tagValue(instance.Tags || [], "Name");
}

function instanceState(instance) {
  if (typeof instance.State === "string") return instance.State;
  return instance.State?.Name || "unknown";
}

function instanceType(instance) {
  return instance.Type || instance.InstanceType || "unknown";
}

function instanceProfile(instance) {
  return instance.Profile || instance.IamInstanceProfile?.Arn || "";
}

function roleFromDbId(id = "") {
  const lower = id.toLowerCase();
  if (lower.includes("restore") || lower.includes("test")) return "restore-test";
  if (lower.includes("afs1") || lower.includes("capetown") || lower.includes("dr")) return "dr";
  if (lower.includes("aps1") || lower.includes("mumbai") || lower.includes("prod-db")) return "primary-or-regional-prod";
  return "unknown";
}

function roleFromEc2(instance) {
  const text = `${instanceName(instance)} ${instanceProfile(instance)} ${instance.InstanceId || ""}`.toLowerCase();
  if (text.includes("github") || text.includes("runner")) return "github-runner";
  if (text.includes("asg-web")) return "asg-node";
  if (text.includes("capetown") || text.includes("mumbai") || text.includes("london") || text.includes("prod")) return "production-or-dr-node";
  return "unknown";
}

function candidate({
  actionCategory,
  blastRadius,
  confidence,
  evidence = [],
  monthlySavingRange = [0, 0],
  recommendation,
  region,
  requiredConsoleEvidence = [],
  resourceId,
  resourceName = "",
  resourceType,
  risk,
  rollbackPath,
  service,
}) {
  return {
    actionCategory,
    blastRadius,
    classification: actionCategory,
    confidence,
    evidence,
    monthlySavingRange,
    recommendation,
    region: region || "unknown",
    requiredConsoleEvidence,
    requiresConsoleConfirmation: true,
    resourceId: resourceId || "unknown",
    resourceName,
    resourceType,
    risk,
    rollbackPath,
    service,
  };
}

function buildInventory(evidenceDir) {
  return {
    ec2Instances: readArrayFiles(uniqueFiles(findFilesByName(evidenceDir, ["ec2-instances.json"]).concat(listFiles(evidenceDir).filter((file) => /^ec2-.*\.json$/u.test(path.basename(file))))), ["Reservations", "Instances"])
      .flatMap((item) => (item.Instances ? item.Instances.map((instance) => ({ ...instance, Region: item.Region || regionFromFile(JSON.stringify(item)) })) : [item])),
    ebsSnapshots: readArrayFiles(uniqueFiles(findFilesByName(evidenceDir, ["ebs-snapshots.json"]).concat(listFiles(evidenceDir).filter((file) => /^ebs-snapshots-.*\.json$/u.test(path.basename(file))))), ["Snapshots"]),
    ebsVolumes: readArrayFiles(uniqueFiles(findFilesByName(evidenceDir, ["ebs-volumes.json"]).concat(listFiles(evidenceDir).filter((file) => /^ebs-volumes-.*\.json$/u.test(path.basename(file))))), ["Volumes"]),
    elasticacheClusters: readArrayFiles(uniqueFiles(findFilesByName(evidenceDir, ["elasticache-cache-clusters.json"]).concat(listFiles(evidenceDir).filter((file) => /^elasticache-.*\.json$/u.test(path.basename(file))))), ["CacheClusters"]),
    natGateways: readArrayFiles(uniqueFiles(findFilesByName(evidenceDir, ["nat-gateways.json"]).concat(listFiles(evidenceDir).filter((file) => /^nat-.*\.json$/u.test(path.basename(file))))), ["NatGateways"]),
    rdsInstances: readArrayFiles(uniqueFiles(findFilesByName(evidenceDir, ["rds-db-instances.json"]).concat(listFiles(evidenceDir).filter((file) => /^rds-.*\.json$/u.test(path.basename(file)) && !path.basename(file).includes("snapshot")))), ["DBInstances"]),
    rdsSnapshots: readArrayFiles(uniqueFiles(findFilesByName(evidenceDir, ["rds-manual-snapshots.json"]).concat(listFiles(evidenceDir).filter((file) => /^rds-.*snapshot.*\.json$/u.test(path.basename(file))))), ["DBSnapshots", "Snapshots"]),
  };
}

function normalizeEc2Instances(evidenceDir) {
  const files = uniqueFiles(findFilesByName(evidenceDir, ["ec2-instances.json"]).concat(listFiles(evidenceDir).filter((file) => /^ec2-.*\.json$/u.test(path.basename(file)))));
  const seen = new Set();
  const instances = [];
  for (const file of files) {
    if (seen.has(file)) continue;
    seen.add(file);
    const region = regionFromFile(file);
    const data = readJsonOptional(file, []);
    if (Array.isArray(data)) {
      for (const item of data) instances.push({ ...item, Region: item.Region || region });
      continue;
    }
    for (const reservation of data.Reservations || []) {
      for (const instance of reservation.Instances || []) instances.push({ ...instance, Region: instance.Region || region });
    }
    for (const instance of data.Instances || []) instances.push({ ...instance, Region: instance.Region || region });
  }
  return instances;
}

function classifyResources(evidenceDir, legacyResources = []) {
  const inventory = buildInventory(evidenceDir);
  inventory.ec2Instances = normalizeEc2Instances(evidenceDir);
  const candidates = [];

  for (const db of inventory.rdsInstances) {
    const id = db.DBInstanceIdentifier || db.DBClusterIdentifier || "unknown";
    candidates.push(candidate({
      actionCategory: ACTION_CATEGORIES.CANDIDATE_RIGHTSIZE_AFTER_METRICS,
      blastRadius: "HIGH: production data path, QR verification, release rollback, and DR posture can be affected.",
      confidence: "High",
      evidence: [
        `role=${roleFromDbId(id)}`,
        `class=${db.DBInstanceClass || "unknown"}`,
        `engine=${db.Engine || "unknown"} ${db.EngineVersion || ""}`.trim(),
        `status=${db.DBInstanceStatus || "unknown"}`,
        `multiAZ=${String(db.MultiAZ ?? "unknown")}`,
        `storage=${db.AllocatedStorage ?? "unknown"}GiB ${db.StorageType || ""}`.trim(),
        `backupRetentionDays=${db.BackupRetentionPeriod ?? "unknown"}`,
      ],
      monthlySavingRange: [25, 180],
      recommendation: "Do not delete. Review metrics-backed class, Multi-AZ, storage, backup, and DR posture before a future right-size proposal.",
      region: db.Region || db.AvailabilityZone?.replace(/[a-z]$/u, ""),
      requiredConsoleEvidence: [
        "CloudWatch CPU, free memory, connections, storage, IOPS, read/write latency.",
        "Backup retention, latest automated/manual snapshot, restore test evidence.",
        "Application dependency and rollback owner approval.",
      ],
      resourceId: id,
      resourceType: "DB instance",
      risk: "HIGH",
      rollbackPath: "Restore from verified snapshot or revert to previous class during an approved maintenance window.",
      service: "RDS",
    }));
  }

  for (const snapshot of inventory.rdsSnapshots) {
    candidates.push(candidate({
      actionCategory: ACTION_CATEGORIES.NEVER_DELETE_WITHOUT_BACKUP,
      blastRadius: "HIGH: removes recovery evidence unless retention and restore alternatives are proven.",
      confidence: "High",
      evidence: [
        `db=${snapshot.DBInstanceIdentifier || "unknown"}`,
        `status=${snapshot.Status || "unknown"}`,
        `created=${snapshot.SnapshotCreateTime || snapshot.StartTime || "unknown"}`,
        `type=${snapshot.SnapshotType || "unknown"}`,
      ],
      monthlySavingRange: [0, 5],
      recommendation: "Keep until a retention policy, recovery purpose, owner decision, and replacement backup path are documented.",
      region: snapshot.Region || snapshot.AvailabilityZone?.replace(/[a-z]$/u, ""),
      requiredConsoleEvidence: [
        "Snapshot ARN, source DB, age, recovery purpose, restore path, and owner approval.",
        "Backup replacement evidence before any future cleanup request.",
      ],
      resourceId: snapshot.DBSnapshotIdentifier || snapshot.SnapshotId || "unknown",
      resourceType: "RDS manual snapshot",
      risk: "HIGH",
      rollbackPath: "No rollback after snapshot removal unless another verified backup exists; this is blocked without backup proof.",
      service: "RDS",
    }));
  }

  for (const cluster of inventory.elasticacheClusters) {
    const nodeCount = numeric(cluster.NumCacheNodes, 1);
    candidates.push(candidate({
      actionCategory: ACTION_CATEGORIES.CANDIDATE_RIGHTSIZE_AFTER_METRICS,
      blastRadius: "HIGH: cache changes can affect login/session behavior, verification latency, rate limits, and release stability.",
      confidence: "High",
      evidence: [
        `cluster=${cluster.CacheClusterId || "unknown"}`,
        `nodeType=${cluster.CacheNodeType || "unknown"}`,
        `nodes=${nodeCount}`,
        `engine=${cluster.Engine || "unknown"} ${cluster.EngineVersion || ""}`.trim(),
        `status=${cluster.CacheClusterStatus || "unknown"}`,
        `replicationGroup=${cluster.ReplicationGroupId || "none"}`,
        `snapshotRetention=${cluster.SnapshotRetentionLimit ?? "unknown"}`,
      ],
      monthlySavingRange: [20, cluster.CacheNodeType?.includes("r7g.large") ? 160 : 60],
      recommendation: "High-priority right-size or topology review only after cache metrics and app dependency proof.",
      region: cluster.Region || cluster.PreferredAvailabilityZone?.replace(/[a-z]$/u, ""),
      requiredConsoleEvidence: [
        "CPU, database memory usage percentage, evictions, current connections, network bytes.",
        "Replication role, failover behavior, snapshot settings, and application dependency.",
      ],
      resourceId: cluster.CacheClusterId,
      resourceType: "Cache cluster",
      risk: "HIGH",
      rollbackPath: "Revert to previous node class/topology from approved change plan; verify cache warm-up and app health.",
      service: "ElastiCache",
    }));
  }

  if (inventory.elasticacheClusters.length === 0) {
    candidates.push(candidate({
      actionCategory: ACTION_CATEGORIES.BLOCKED_UNTIL_MORE_EVIDENCE,
      blastRadius: "UNKNOWN: Cost Explorer shows high spend but cluster inventory is missing.",
      confidence: "High",
      evidence: ["ElastiCache is a top cost driver but no local cache cluster inventory was found."],
      monthlySavingRange: [40, 180],
      recommendation: "Collect ElastiCache inventory and metrics before any recommendation.",
      region: "unknown",
      requiredConsoleEvidence: ["Cluster list, node type/count, CPU, memory, evictions, connections, replication, snapshots."],
      resourceId: "elasticache-inventory-missing",
      resourceType: "Missing inventory",
      risk: "MEDIUM",
      rollbackPath: "No action can be planned until inventory exists.",
      service: "ElastiCache",
    }));
  }

  for (const instance of inventory.ec2Instances) {
    const role = roleFromEc2(instance);
    const state = instanceState(instance);
    const isProd = role === "production-or-dr-node" || role === "asg-node";
    candidates.push(candidate({
      actionCategory: isProd ? ACTION_CATEGORIES.KEEP : ACTION_CATEGORIES.REVIEW_REQUIRED,
      blastRadius: isProd ? "HIGH: production/DR/ASG web capacity." : "MEDIUM: unknown or runner capacity can affect releases.",
      confidence: "Medium",
      evidence: [
        `role=${role}`,
        `name=${instanceName(instance) || "none"}`,
        `state=${state}`,
        `type=${instanceType(instance)}`,
        `launch=${instance.LaunchTime || "unknown"}`,
        `profile=${instanceProfile(instance) || "none"}`,
      ],
      monthlySavingRange: isProd ? [0, 0] : [5, 40],
      recommendation: isProd
        ? "Keep production/DR/ASG nodes unless metrics and release dependencies prove a right-size path."
        : "Review scheduler or class only after CPU, network, disk, and release dependency evidence.",
      region: instance.Region,
      requiredConsoleEvidence: [
        "CPU, network, disk, public IPv4, ASG membership, desired/min/max, release gate dependency.",
        "Owner approval and rollback launch path.",
      ],
      resourceId: instance.InstanceId,
      resourceName: instanceName(instance),
      resourceType: "EC2 instance",
      risk: isProd ? "HIGH" : "MEDIUM",
      rollbackPath: "Restore previous instance class or ASG desired capacity from approved launch template/AMI.",
      service: "EC2",
    }));
  }

  for (const volume of inventory.ebsVolumes) {
    const attachments = Array.isArray(volume.Attachments) ? volume.Attachments : [];
    const available = volume.State === "available" && attachments.length === 0;
    candidates.push(candidate({
      actionCategory: available ? ACTION_CATEGORIES.CANDIDATE_DELETE_AFTER_BACKUP_AND_APPROVAL : ACTION_CATEGORIES.KEEP,
      blastRadius: available ? "LOW to MEDIUM: unattached volume may still be rollback/recovery evidence." : "HIGH if attached to production compute.",
      confidence: available ? "High" : "Medium",
      evidence: [
        `state=${volume.State || "unknown"}`,
        `sizeGiB=${volume.SizeGiB ?? volume.Size ?? "unknown"}`,
        `type=${volume.VolumeType || "unknown"}`,
        `encrypted=${String(volume.Encrypted ?? "unknown")}`,
        `attachments=${attachments.length}`,
      ],
      monthlySavingRange: available ? [1, Math.max(1, numeric(volume.SizeGiB ?? volume.Size) * 0.1)] : [0, 0],
      recommendation: available
        ? "Only a future approval-gated cleanup candidate after backup, owner, age, and console proof."
        : "Keep attached volumes; separately review encryption and gp2-to-gp3 modernization.",
      region: volume.Region || volume.AvailabilityZone?.replace(/[a-z]$/u, ""),
      requiredConsoleEvidence: ["Volume ID, attachment state, age, tags, latest snapshot, owner decision, backup path."],
      resourceId: volume.VolumeId,
      resourceType: "EBS volume",
      risk: available ? "MEDIUM" : "HIGH",
      rollbackPath: "Recreate from verified snapshot and reattach during approved maintenance if future cleanup is approved.",
      service: "EC2 Other",
    }));
  }

  for (const snapshot of inventory.ebsSnapshots) {
    candidates.push(candidate({
      actionCategory: ACTION_CATEGORIES.NEVER_DELETE_WITHOUT_BACKUP,
      blastRadius: "MEDIUM to HIGH: snapshot may be rollback or image recovery evidence.",
      confidence: "Medium",
      evidence: [`volume=${snapshot.VolumeId || "unknown"}`, `started=${snapshot.StartTime || "unknown"}`, `state=${snapshot.State || "unknown"}`],
      monthlySavingRange: [0, 5],
      recommendation: "Design retention policy first; never treat snapshots as deletion-safe without restore path and owner approval.",
      region: snapshot.Region || "unknown",
      requiredConsoleEvidence: ["Snapshot origin, AMI association, recovery purpose, age, owner approval, replacement backup."],
      resourceId: snapshot.SnapshotId,
      resourceType: "EBS snapshot",
      risk: "HIGH",
      rollbackPath: "Blocked unless an equivalent verified restore point exists.",
      service: "EC2 Other",
    }));
  }

  for (const nat of inventory.natGateways) {
    candidates.push(candidate({
      actionCategory: ACTION_CATEGORIES.REVIEW_REQUIRED,
      blastRadius: "HIGH: NAT path can break private subnet egress, package pulls, health checks, and release operations.",
      confidence: "High",
      evidence: [
        `state=${nat.State || "unknown"}`,
        `vpc=${nat.VpcId || "unknown"}`,
        `subnet=${nat.SubnetId || "unknown"}`,
        `publicIp=${nat.PublicIp || nat.NatGatewayAddresses?.[0]?.PublicIp || "unknown"}`,
        `name=${tagValue(nat.Tags || []) || "none"}`,
      ],
      monthlySavingRange: [20, 90],
      recommendation: "Review whether endpoints or route changes can reduce NAT cost, but do not change NAT without route table and egress proof.",
      region: nat.Region,
      requiredConsoleEvidence: ["Route tables, private subnet egress requirements, NAT bytes/hours, VPC endpoints alternative, rollback route plan."],
      resourceId: nat.NatGatewayId,
      resourceType: "NAT gateway",
      risk: "HIGH",
      rollbackPath: "Restore previous route table targets and NAT topology from captured pre-change evidence.",
      service: "VPC",
    }));
  }

  for (const resource of legacyResources) {
    if (resource.service === "route53" && resource.resourceType === "record") {
      candidates.push(candidate({
        actionCategory: /dr-capetown|dr-mumbai/iu.test(`${resource.resourceId} ${resource.resourceName}`) ? ACTION_CATEGORIES.REVIEW_REQUIRED : ACTION_CATEGORIES.KEEP,
        blastRadius: "CRITICAL: DNS changes can break production routing, DR, certificate validation, or failover.",
        confidence: "High",
        evidence: resource.evidence || ["Legacy Route 53 classification evidence."],
        monthlySavingRange: [0, 0],
        recommendation: "Keep production and validation records unless a separate DNS approval workflow proves a stale non-production record.",
        region: resource.region || "global",
        requiredConsoleEvidence: ["Hosted zone, record name/type/policy, target, certificate relation, failover policy, owner approval."],
        resourceId: resource.resourceId || resource.resourceName,
        resourceName: resource.resourceName,
        resourceType: "Route 53 record",
        risk: "CRITICAL",
        rollbackPath: "Use approved DNS rollback plan only; this analyzer never changes DNS.",
        service: "Route 53",
      }));
    }
    if (resource.resourceType === "target-group") {
      candidates.push(candidate({
        actionCategory: ACTION_CATEGORIES.REVIEW_REQUIRED,
        blastRadius: "MEDIUM to HIGH: target groups can be referenced by listeners, ASGs, and rollout health.",
        confidence: resource.classification === "SAFE_TO_DELETE_LATER" ? "Medium" : "Low",
        evidence: resource.evidence || [],
        monthlySavingRange: [0, 5],
        recommendation: "Review only. Require screenshots proving zero targets and no listener, rule, ASG, or Route 53 dependency.",
        region: resource.region,
        requiredConsoleEvidence: ["Target health, listener/rule association, ASG references, tags, owner approval."],
        resourceId: resource.resourceId || resource.resourceName,
        resourceName: resource.resourceName,
        resourceType: "Target group",
        risk: "MEDIUM",
        rollbackPath: "Recreate target group and listener/ASG attachment from captured config if future approval exists.",
        service: "ELB",
      }));
    }
  }

  return candidates;
}

function discoverLegacyClassifications(root = process.cwd()) {
  return [
    path.join(root, "artifacts", "aws-cleanup-inventory"),
    path.join(root, "documents", "ops", "evidence"),
  ]
    .flatMap((dir) => listFiles(dir))
    .filter((file) => path.basename(file) === "classified-resources.json")
    .sort()
    .map((file) => ({ file, data: readJsonOptional(file, {}) }));
}

function buildCostModel(evidenceDir, screenshotsDir = "") {
  const forecastData = readJsonOptional(path.join(evidenceDir, "cost-current-month-forecast.json"), {});
  const forecast = numeric(forecastData?.Total?.Amount ?? forecastData?.ForecastResultsByTime?.[0]?.MeanValue, DEFAULT_FORECAST_USD);
  const serviceJson = mergeMax(
    serviceCostFromJson(path.join(evidenceDir, "cost-mtd-by-service.json")),
    serviceCostFromJson(path.join(evidenceDir, "cost-daily-by-service.json")),
    serviceCostFromJson(path.join(evidenceDir, "cost-last-30-days-by-service.json")),
  );
  const usageJson = {
    RDS: parseUsageTypeCost(path.join(evidenceDir, "10-cost-rds-usage-type.json")),
    ElastiCache: parseUsageTypeCost(path.join(evidenceDir, "11-cost-elasticache-usage-type.json")),
    "EC2 Other": parseUsageTypeCost(path.join(evidenceDir, "12-cost-ec2-other-usage-type.json")),
    VPC: parseUsageTypeCost(path.join(evidenceDir, "13-cost-vpc-usage-type.json")),
  };
  const usageServiceTotals = Object.fromEntries(Object.entries(usageJson).map(([service, value]) => [service, value.total]));
  const csvReports = costCsvFiles(evidenceDir, screenshotsDir).map(parseCostCsv).filter(Boolean).sort((a, b) => b.total - a.total);
  const serviceCsv = mergeMax(...csvReports.filter((report) => report.kind === "service").map((report) => report.values));
  const observed = mergeMax(serviceJson, usageServiceTotals, serviceCsv);
  const totalObserved = Math.max(sumValues(observed), ...csvReports.map((report) => report.total).filter(Boolean), 0);
  const taxableObserved = Math.max(totalObserved - (observed.Tax || 0), 1);
  const drivers = Object.entries(observed)
    .filter(([service]) => service !== "Total costs")
    .map(([service, observedCost]) => ({
      action: serviceAction(service),
      confidence: serviceCsv[service] || usageServiceTotals[service] ? "High" : "Medium",
      monthlyPressure: service === "Tax" ? observedCost : (observedCost / taxableObserved) * forecast,
      observedCost,
      service,
      usageTypes: usageJson[service]?.usageTypes?.slice(0, 12) || [],
    }))
    .sort((a, b) => b.observedCost - a.observedCost);
  return {
    csvReports,
    drivers,
    forecast,
    observed,
    requiredSavingsHigh: Math.max(0, forecast - TARGET_CEILING_HIGH_USD),
    requiredSavingsLow: Math.max(0, forecast - TARGET_CEILING_LOW_USD),
    targetHigh: TARGET_CEILING_HIGH_USD,
    targetLow: TARGET_CEILING_LOW_USD,
    totalObserved,
    usageJson,
  };
}

function serviceAction(service) {
  const actions = {
    CloudWatch: "Review log retention and metrics volume; approval required for policy changes.",
    "EC2 Compute": "Review production, DR, ASG, and GitHub runner footprint after metrics.",
    "EC2 Other": "Break down NAT, EBS, snapshots, transfer, and public IPv4 evidence.",
    ECR: "Review lifecycle policy only after workflow references are checked.",
    ECS: "Review old London ECS leftovers only with workflow evidence.",
    ELB: "Keep active regional ALBs; review orphan target groups with console proof.",
    ElastiCache: "Metrics-backed right-size or topology review.",
    RDS: "Metrics-backed right-size and DR database posture review.",
    "Route 53": "Keep production and validation records.",
    S3: "Review lifecycle policy; do not clear production buckets.",
    "Secrets Manager": "Review stale secrets only with access evidence.",
    Tax: "Not directly optimizable; reduce taxable service spend.",
    VPC: "Review NAT, public IPv4, route tables, and endpoint alternatives.",
    WAF: "Keep protections; review unused Web ACLs only with evidence.",
  };
  return actions[service] || "Observe and gather service-specific evidence.";
}

function savingsModel(costs, candidates) {
  const model = [
    {
      candidate: "RDS right-sizing / DR DB posture review",
      confidence: "Medium",
      estimatedMonthlySavings: [50, 180],
      operationalBlastRadius: "HIGH",
      requiredConsoleEvidence: "CPU, memory, connections, IOPS, storage, backups, latest snapshot, restore path.",
      risk: "HIGH",
      rollbackPath: "Revert class or restore from verified snapshot during approved maintenance.",
    },
    {
      candidate: "ElastiCache right-sizing / regional cache topology review",
      confidence: "Medium",
      estimatedMonthlySavings: [60, 180],
      operationalBlastRadius: "HIGH",
      requiredConsoleEvidence: "CPU, memory, evictions, connections, network, replication role, app dependency.",
      risk: "HIGH",
      rollbackPath: "Revert node class/topology and verify cache warm-up.",
    },
    {
      candidate: "EC2/ASG/GitHub runner footprint review",
      confidence: "Medium",
      estimatedMonthlySavings: [20, 70],
      operationalBlastRadius: "MEDIUM to HIGH",
      requiredConsoleEvidence: "CPU, network, disk, ASG desired/min/max, runner queue, release dependency.",
      risk: "MEDIUM",
      rollbackPath: "Restore prior ASG desired capacity or instance class.",
    },
    {
      candidate: "NAT/VPC and public IPv4 review",
      confidence: "High",
      estimatedMonthlySavings: [20, 90],
      operationalBlastRadius: "HIGH",
      requiredConsoleEvidence: "Route tables, private subnet egress, NAT bytes/hours, endpoint alternative, rollback route plan.",
      risk: "HIGH",
      rollbackPath: "Restore previous routes and NAT topology.",
    },
    {
      candidate: "EBS volume and snapshot lifecycle review",
      confidence: candidates.some((item) => item.actionCategory === ACTION_CATEGORIES.CANDIDATE_DELETE_AFTER_BACKUP_AND_APPROVAL) ? "Medium" : "Low",
      estimatedMonthlySavings: [0, 25],
      operationalBlastRadius: "MEDIUM",
      requiredConsoleEvidence: "Attachment, source volume, recovery purpose, age, owner, backup confirmation.",
      risk: "MEDIUM",
      rollbackPath: "Restore from verified snapshot if one exists.",
    },
    {
      candidate: "Small services cleanup after big drivers",
      confidence: "Medium",
      estimatedMonthlySavings: [5, 30],
      operationalBlastRadius: "LOW to MEDIUM",
      requiredConsoleEvidence: "CloudWatch retention, ECR lifecycle, S3 lifecycle, WAF/Secrets access evidence.",
      risk: "LOW to MEDIUM",
      rollbackPath: "Revert retention/lifecycle settings from captured config.",
    },
  ];
  return {
    currentForecastUsd: costs.forecast,
    requiredSavingsToHighCeilingUsd: costs.requiredSavingsHigh,
    requiredSavingsToLowCeilingUsd: costs.requiredSavingsLow,
    targetCeilingUsd: [TARGET_CEILING_LOW_USD, TARGET_CEILING_HIGH_USD],
    topCandidates: model,
  };
}

function actionSummary(candidates) {
  return Object.values(ACTION_CATEGORIES).map((actionCategory) => ({
    actionCategory,
    count: candidates.filter((candidateItem) => candidateItem.actionCategory === actionCategory).length,
  }));
}

function sha256(filePath) {
  return createHash("sha256").update(readFileSync(filePath)).digest("hex");
}

function writeChecksums(outputDir, files) {
  const checksumFile = path.join(outputDir, "SHA256SUMS.txt");
  const lines = files.map((file) => `${sha256(file)}  ${path.basename(file)}`);
  writeFileSync(checksumFile, `${lines.join("\n")}\n`);
  return checksumFile;
}

export function analyzeCostOptimization(options = {}, root = process.cwd()) {
  const selected = selectEvidence(options, root);
  const screenshots = screenshotFiles(selected.evidenceDir, options.screenshotsDir);
  const legacy = discoverLegacyClassifications(root);
  const legacyResources = legacy.flatMap((entry) => entry.data?.resources || []);
  const costs = buildCostModel(selected.evidenceDir, options.screenshotsDir);
  const candidates = classifyResources(selected.evidenceDir, legacyResources);
  const generatedAt = new Date().toISOString();
  const runTimestamp = options.timestamp || utcStamp();
  const outputRoot = path.resolve(root, options.outputRoot || path.join("artifacts", "aws-cost-optimization"));
  const outputDir = path.join(outputRoot, runTimestamp);
  const downloadsDir = path.join(options.downloadsRoot || DOWNLOAD_REPORT_ROOT, runTimestamp);
  mkdirSync(outputDir, { recursive: true });
  mkdirSync(downloadsDir, { recursive: true });

  const report = {
    actionSummary: actionSummary(candidates),
    candidates,
    costs,
    evidence: {
      costCsvExports: costs.csvReports.map((item) => item.filePath),
      legacyClassifications: legacy.map((item) => item.file),
      screenshots,
      screenshotsDir: options.screenshotsDir || "",
      selectedEvidenceDir: selected.evidenceDir,
      sourcePath: selected.sourcePath,
      sourceType: selected.sourceType,
    },
    generatedAt,
    outputDir,
    downloadsDir,
    savingsModel: savingsModel(costs, candidates),
    safety: {
      futureActionRequirement: "Analysis first, console proof second, approval third, mutation last.",
      message: "No AWS mutation was performed.",
      readOnly: true,
    },
    target: {
      conservativeCeilingUsd: [TARGET_CEILING_LOW_USD, TARGET_CEILING_HIGH_USD],
      forecastUsd: costs.forecast,
      requiredSavingsUsd: costs.requiredSavingsHigh,
    },
  };

  const outputs = {
    actionRegister: path.join(outputDir, "cost-action-register.tsv"),
    checklist: path.join(outputDir, "proposed-console-review-checklist.md"),
    json: path.join(outputDir, "cost-optimization-report.json"),
    markdown: path.join(outputDir, "cost-optimization-report.md"),
    summary: path.join(outputDir, "cost-optimization-summary.txt"),
  };
  writeFileSync(outputs.markdown, renderMarkdown(report));
  writeFileSync(outputs.json, `${JSON.stringify(report, null, 2)}\n`);
  writeFileSync(outputs.summary, renderSummary(report));
  writeFileSync(outputs.checklist, renderConsoleChecklist(report));
  writeFileSync(outputs.actionRegister, renderActionRegister(report));
  outputs.checksums = writeChecksums(outputDir, Object.values(outputs));

  for (const file of Object.values(outputs)) copyFileSync(file, path.join(downloadsDir, path.basename(file)));
  writeChecksums(downloadsDir, Object.values(outputs).map((file) => path.join(downloadsDir, path.basename(file))).filter((file) => path.basename(file) !== "SHA256SUMS.txt"));

  return { ...report, outputs };
}

function renderSummary(report) {
  const topDrivers = report.costs.drivers.slice(0, 10).map((driver) => `- ${driver.service}: observed ${currency(driver.observedCost)}, pressure ${currency(driver.monthlyPressure)}, ${driver.action}`);
  const topActions = report.savingsModel.topCandidates.map((item) => `- ${item.candidate}: ${currency(item.estimatedMonthlySavings[0])}-${currency(item.estimatedMonthlySavings[1])}/month, risk ${item.risk}, confidence ${item.confidence}`);
  return [
    "MSCQR AWS Cost Optimization Summary",
    `Generated: ${report.generatedAt}`,
    `Selected evidence folder: ${report.evidence.selectedEvidenceDir}`,
    `Downloads report path: ${report.downloadsDir}`,
    `Forecast: ${currency(report.target.forecastUsd)}`,
    `Target ceiling: ${currency(report.target.conservativeCeilingUsd[0])}-${currency(report.target.conservativeCeilingUsd[1])}`,
    `Required savings gap: ${currency(report.savingsModel.requiredSavingsToHighCeilingUsd)}-${currency(report.savingsModel.requiredSavingsToLowCeilingUsd)}`,
    "No AWS mutation was performed.",
    "",
    "High-confidence cost drivers:",
    ...topDrivers,
    "",
    "Top conservative savings workstreams:",
    ...topActions,
    "",
    "CTO recommendation: do not randomly delete legacy services first. Reduce the big drivers with evidence-backed RDS, ElastiCache, EC2/ASG, NAT/VPC, and EBS lifecycle reviews.",
    "",
  ].join("\n");
}

function renderDriverTable(report) {
  return [
    "| Service | Observed cost | Approx monthly pressure | Confidence | Action |",
    "| --- | ---: | ---: | --- | --- |",
    ...report.costs.drivers.slice(0, 14).map((driver) => `| ${driver.service} | ${currency(driver.observedCost)} | ${currency(driver.monthlyPressure)} | ${driver.confidence} | ${driver.action} |`),
  ].join("\n");
}

function renderUsageTables(report) {
  return report.costs.drivers
    .filter((driver) => driver.usageTypes.length > 0)
    .map((driver) => [
      `### ${driver.service} usage types`,
      "| Usage type | Observed cost | Usage quantity |",
      "| --- | ---: | ---: |",
      ...driver.usageTypes.slice(0, 10).map((item) => `| ${item.usageType} | ${currency(item.amount)} | ${numeric(item.usageQuantity).toFixed(2)} ${item.unit || ""} |`),
    ].join("\n"))
    .join("\n\n");
}

function renderSavingsModel(report) {
  return [
    "| Candidate | Estimated monthly saving | Confidence | Safety risk | Operational blast radius | Rollback path | Required console evidence |",
    "| --- | ---: | --- | --- | --- | --- | --- |",
    ...report.savingsModel.topCandidates.map((item) => `| ${item.candidate} | ${currency(item.estimatedMonthlySavings[0])}-${currency(item.estimatedMonthlySavings[1])} | ${item.confidence} | ${item.risk} | ${item.operationalBlastRadius} | ${item.rollbackPath} | ${item.requiredConsoleEvidence} |`),
  ].join("\n");
}

function renderCandidateTable(report) {
  return [
    "| Service | Type | Region | Resource | Action category | Saving range | Risk | Recommendation |",
    "| --- | --- | --- | --- | --- | ---: | --- | --- |",
    ...report.candidates.slice(0, 80).map((item) => `| ${item.service} | ${item.resourceType} | ${item.region} | ${item.resourceId} | ${item.actionCategory} | ${currency(item.monthlySavingRange[0])}-${currency(item.monthlySavingRange[1])} | ${item.risk} | ${item.recommendation} |`),
  ].join("\n");
}

function renderMarkdown(report) {
  return `# MSCQR AWS Cost Optimization Report

Generated: ${report.generatedAt}

No AWS mutation was performed.

## Executive summary

- Current AWS forecast: ${currency(report.target.forecastUsd)} per month.
- Business target: below GBP 600 including taxes. Conservative AWS USD ceiling: ${currency(report.target.conservativeCeilingUsd[0])}-${currency(report.target.conservativeCeilingUsd[1])}.
- Required savings gap: ${currency(report.savingsModel.requiredSavingsToHighCeilingUsd)}-${currency(report.savingsModel.requiredSavingsToLowCeilingUsd)} per month.
- Best next action: metrics-backed RDS and ElastiCache review, then EC2/ASG/GitHub runner footprint, NAT/VPC, EBS lifecycle, and finally small services.
- Production invariants remain protected: Route 53 three-region policy, non-mutating failover monitor, no production MinIO, S3 object storage mode, release train/gate split, QR signing, rollback, and DR safety.

## Immediate safe informational findings

- This pass parsed local files only.
- The report contains no automatic AWS action.
- All future work requires visual AWS Console confirmation and explicit human approval.
- RDS snapshots and production Route 53 records are not deletion-safe.

## High-confidence cost drivers

${renderDriverTable(report)}

Tax is not directly optimizable. It decreases only when taxable service spend decreases.

## Usage-type evidence

${renderUsageTables(report) || "No usage-type evidence was found."}

## Conservative savings model

${renderSavingsModel(report)}

## Action categories

- KEEP: production or required infrastructure.
- OBSERVE_ONLY: informational finding only.
- REVIEW_REQUIRED: needs more human review before any proposal.
- CANDIDATE_RIGHTSIZE_AFTER_METRICS: possible future size/topology change after metrics and approval.
- CANDIDATE_STOP_AFTER_APPROVAL: reversible future stop only after proof and approval.
- CANDIDATE_DELETE_AFTER_BACKUP_AND_APPROVAL: future cleanup only with backup, restore path, console proof, and approval.
- NEVER_DELETE_WITHOUT_BACKUP: blocked unless backup/restore evidence and owner decision exist.
- BLOCKED_UNTIL_MORE_EVIDENCE: no recommendation until missing evidence is collected.

## Service-specific analysis

### RDS

RDS is a primary savings workstream, not a cleanup target. DB instances are right-size candidates only after CPU, free memory, connections, storage, IOPS, backup retention, and latest snapshot evidence. Manual snapshots are \`${ACTION_CATEGORIES.NEVER_DELETE_WITHOUT_BACKUP}\`.

### ElastiCache

ElastiCache is one of the biggest drivers. Cache clusters are \`${ACTION_CATEGORIES.CANDIDATE_RIGHTSIZE_AFTER_METRICS}\` only; required proof includes CPU, memory, evictions, current connections, network bytes, replication role, snapshots, and application dependency.

### EC2 / ASG

Production, DR, and ASG nodes are kept unless metrics prove a safe right-size path. GitHub runner or unknown nodes require release gate dependency evidence before scheduler or class changes.

### EC2 Other

EBS volumes and snapshots require attachment, origin, owner, age, recovery purpose, and backup confirmation. Snapshots are never deletion-safe without backup evidence.

### VPC / NAT

NAT gateways are high-impact review candidates only. Required proof includes route tables, private subnet egress, NAT bytes/hours, VPC endpoints alternative, and rollback route plan.

### ELB

Active regional ALBs and Route 53 policy targets stay protected. Orphan target groups are \`${ACTION_CATEGORIES.REVIEW_REQUIRED}\` until console evidence proves no listeners, targets, ASG references, or DNS references.

### S3

Production artifact buckets and ALB log buckets are KEEP or REVIEW_REQUIRED. Lifecycle policy review requires object count, size, last-modified distribution, lifecycle state, and app dependency.

### Route 53 / ACM

Production geolocation records and ACM validation records are protected. Validation records may be reviewed only with certificate evidence.

### IAM

Roles and policies are not cleanup targets here. ECS or old roles are REVIEW_REQUIRED only and need access-last-used/workflow evidence.

## Candidate action register preview

${renderCandidateTable(report)}

## Console click-by-click review

${consoleSteps().join("\n\n")}

## Approval requirements

Every future action requires screenshot, resource ARN/ID, current cost evidence, owner decision, rollback/restore path, backup confirmation, explicit manual approval, and post-action verification in a separate approved pass.

## Download path

\`${report.downloadsDir}\`
`;
}

function consoleSteps() {
  return [
    "### Cost Explorer\n1. Open AWS Console > Billing and Cost Management > Cost Explorer.\n2. Set date range to current month and last 30 days.\n3. Group by Service, then Usage type for RDS, ElastiCache, EC2-Other, VPC, and EC2 Compute.\n4. Capture forecast, service totals, usage-type breakdowns, and export CSV.",
    "### RDS\n1. Open AWS Console > RDS > Databases.\n2. Select each MSCQR DB by region and identifier.\n3. Capture class, engine, Multi-AZ, storage, backup retention, deletion protection, CPU, free memory, connections, IOPS, and latest snapshot.\n4. Confirm restore path and owner approval before any future right-size proposal.",
    "### ElastiCache\n1. Open AWS Console > ElastiCache > clusters.\n2. Capture cluster ID, node type/count, engine, status, replication group, snapshot retention, CPU, memory, evictions, connections, and network bytes.\n3. Confirm application dependency before any topology or class proposal.",
    "### EC2 / ASG\n1. Open AWS Console > EC2 > Instances and Auto Scaling Groups.\n2. Capture instance ID, name, state, class, launch time, public IPv4, instance profile, ASG desired/min/max, and target groups.\n3. Separate production, DR, ASG, GitHub runner, and unknown nodes.",
    "### EC2 Other / EBS\n1. Open AWS Console > EC2 > Volumes and Snapshots.\n2. Capture attachment state, source volume, size, type, encryption, age, tags, recovery purpose, and latest backup.\n3. Treat snapshots as blocked without backup/restore decision.",
    "### VPC / NAT\n1. Open AWS Console > VPC > NAT gateways and Route tables.\n2. Capture NAT ID, region, state, VPC, subnet, public IP, routes, private subnet egress needs, and NAT bytes/hours.\n3. Compare VPC endpoint alternatives before any future network change.",
    "### Load Balancers / Target Groups\n1. Open AWS Console > EC2 > Load Balancers and Target Groups.\n2. Capture DNS name, listeners, rules, target health, ASG references, tags, and Route 53 aliases.\n3. Keep ALBs serving Africa AF, Europe EU, and default/global policy.",
    "### S3 / ECR / CloudWatch / WAF / Secrets\n1. Capture bucket size/object count/lifecycle, ECR image age/lifecycle/workflow references, CloudWatch stored bytes/retention, WAF associations, and Secrets access evidence.\n2. Review only after owner approval and rollback plan.",
    "### Budgets\n1. Open AWS Console > Billing and Cost Management > Budgets.\n2. Verify monthly budget below the conservative ceiling and service-level alerts for RDS, ElastiCache, EC2, VPC, ELB, and Tax drift.",
  ];
}

function renderConsoleChecklist(report) {
  return [
    "# MSCQR AWS Cost Optimization Proposed Console Review Checklist",
    "",
    "No AWS mutation was performed.",
    "",
    `Selected evidence folder: \`${report.evidence.selectedEvidenceDir}\``,
    `Downloads report path: \`${report.downloadsDir}\``,
    "",
    ...consoleSteps(),
    "",
    "## Per-candidate approval ledger",
    "",
    "| Candidate | Screenshot | ARN/ID | Current cost evidence | Owner decision | Rollback/restore path | Backup confirmation | Manual approval |",
    "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ...report.candidates.slice(0, 80).map((item) => `| ${item.service} ${item.resourceType} ${item.resourceId} | pending | ${item.resourceId} | pending | pending | pending | pending | pending |`),
    "",
  ].join("\n");
}

function tsvCell(value) {
  return String(value ?? "").replace(/\t/gu, " ").replace(/\r?\n/gu, " ");
}

function renderActionRegister(report) {
  const header = [
    "service",
    "resource_type",
    "region",
    "resource_id",
    "action_category",
    "monthly_saving_low_usd",
    "monthly_saving_high_usd",
    "confidence",
    "risk",
    "blast_radius",
    "rollback_path",
    "required_console_evidence",
    "recommendation",
  ];
  const rows = report.candidates.map((item) => [
    item.service,
    item.resourceType,
    item.region,
    item.resourceId,
    item.actionCategory,
    item.monthlySavingRange[0],
    item.monthlySavingRange[1],
    item.confidence,
    item.risk,
    item.blastRadius,
    item.rollbackPath,
    item.requiredConsoleEvidence.join("; "),
    item.recommendation,
  ].map(tsvCell).join("\t"));
  return `${header.join("\t")}\n${rows.join("\n")}\n`;
}

function main() {
  try {
    const options = parseArgs(process.argv.slice(2));
    const result = analyzeCostOptimization(options);
    console.log(`Selected evidence folder: ${result.evidence.selectedEvidenceDir}`);
    console.log(`Forecast: ${currency(result.target.forecastUsd)}`);
    console.log(`Target ceiling: ${currency(result.target.conservativeCeilingUsd[0])}-${currency(result.target.conservativeCeilingUsd[1])}`);
    console.log(`Required savings gap: ${currency(result.savingsModel.requiredSavingsToHighCeilingUsd)}-${currency(result.savingsModel.requiredSavingsToLowCeilingUsd)}`);
    console.log(`Report: ${result.outputs.markdown}`);
    console.log(`Downloads report path: ${result.downloadsDir}`);
    console.log("No AWS mutation was performed.");
  } catch (error) {
    console.error(error.message || String(error));
    process.exit(1);
  }
}

const mainPath = fileURLToPath(import.meta.url);
if (import.meta.url === pathToFileURL(mainPath).href && process.argv[1] === mainPath) main();
