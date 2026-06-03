#!/usr/bin/env node

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import process from "node:process";
import { pathToFileURL } from "node:url";

export const CLASSIFICATIONS = {
  KEEP: "KEEP",
  REVIEW_REQUIRED: "REVIEW_REQUIRED",
  SAFE_TO_STOP: "SAFE_TO_STOP",
  SAFE_TO_DELETE_LATER: "SAFE_TO_DELETE_LATER",
  NEVER_DELETE_WITHOUT_BACKUP: "NEVER_DELETE_WITHOUT_BACKUP",
};

const REQUIRED_REGIONS = ["ap-south-1", "af-south-1", "eu-west-2", "us-east-1"];
const REQUIRED_REGION_FILES = [
  ["ec2-instances.json"],
  ["ebs-volumes.json"],
  ["ebs-snapshots.json"],
  ["elastic-ips.json"],
  ["load-balancers.json", "elbv2-load-balancers.json"],
  ["target-groups.json", "elbv2-target-groups.json"],
  ["auto-scaling-groups.json"],
  ["launch-templates.json"],
  ["security-groups.json"],
  ["network-interfaces.json"],
  ["rds-db-instances.json"],
  ["rds-db-clusters.json"],
  ["rds-manual-snapshots.json"],
  ["ecs-clusters.json"],
  ["ecr-repositories.json"],
  ["acm-certificates.json"],
  ["cloudwatch-alarms.json"],
];

const CURRENT = {
  hostedZoneId: "Z0569586VLFIGGVI7HAZ",
  domainName: "mscqr.com.",
  albDnsNames: new Set([
    "mscqr-mumbai-alb-1249752376.ap-south-1.elb.amazonaws.com",
    "mscqr-capetown-alb-1730011881.af-south-1.elb.amazonaws.com",
    "mscqr-alb-euw2-524835535.eu-west-2.elb.amazonaws.com",
  ]),
  productionAsgs: new Set(["mscqr-mumbai-dr-asg", "mscqr-capetown-dr-asg"]),
  productionInstanceNames: new Set(["mscqr-prod-mumbai", "mscqr-prod-capetown", "mscqr-prod_london", "mscqr-github-actions-runner"]),
  productionBuckets: new Set([
    "mscqr-prod-aps1-artifacts-368992683803-ap-south-1",
    "mscqr-prod-afs1-artifacts-368992683803-af-south-1",
    "mscqr-prod-euw2-artifacts-368992683803-eu-west-2-an",
  ]),
  albLogBuckets: new Set(["mscqr-alb-logs-aps1-368992683803", "mscqr-alb-logs-afs1-368992683803"]),
  keepIamRoles: new Set([
    "github-actions-mscqr-deploy",
    "mscqr-github-auto-failover-readonly",
    "mscqr-asg-web-role-aps1",
    "mscqr-ec2-s3-artifacts-role",
    "mscqr-ec2-s3-artifacts-role-afs1",
    "mscqr-ec2-s3-artifacts-role-aps1",
  ]),
};

const usage = `Usage:
  npm run ops:legacy-cleanup-inventory -- --archive <path>
  npm run ops:legacy-cleanup-inventory -- --inventory-dir <path>

Options:
  --archive <path>        Read a tar.gz inventory archive.
  --inventory-dir <path>  Read an extracted inventory directory.

If no input is supplied, the newest complete archive under artifacts/aws-cleanup-inventory/ is selected.

This tool is read-only. It classifies inventory evidence and writes local reports only.
`;

export function parseArgs(argv) {
  const options = { archive: "", inventoryDir: "" };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    const next = () => {
      const value = argv[index + 1];
      if (!value || value.startsWith("--")) throw new Error(`Missing value for ${arg}`);
      index += 1;
      return value;
    };
    if (arg === "--archive") options.archive = next();
    else if (arg === "--inventory-dir") options.inventoryDir = next();
    else if (arg === "-h" || arg === "--help") {
      console.log(usage);
      process.exit(0);
    } else throw new Error(`Unknown option: ${arg}\n${usage}`);
  }
  if (options.archive && options.inventoryDir) throw new Error("Use either --archive or --inventory-dir, not both.");
  return options;
}

export function resolveArchivePath(inputPath, root = process.cwd()) {
  const absolute = path.resolve(root, inputPath);
  if (existsSync(absolute)) return absolute;
  const fallback = path.join(root, "artifacts", "aws-cleanup-inventory", path.basename(inputPath));
  if (existsSync(fallback)) return fallback;
  throw new Error(`Archive not found: ${inputPath}`);
}

export function extractArchive(archivePath) {
  const tmp = mkdtempSync(path.join(tmpdir(), "mscqr-aws-inventory-"));
  const tar = existsSync("/usr/bin/tar") ? "/usr/bin/tar" : "tar";
  execFileSync(tar, ["-xzf", archivePath, "-C", tmp], { stdio: ["ignore", "pipe", "pipe"] });
  const dirs = readdirSync(tmp)
    .map((name) => path.join(tmp, name))
    .filter((item) => statSync(item).isDirectory());
  if (dirs.length !== 1) throw new Error(`Archive must contain exactly one inventory root directory: ${archivePath}`);
  return dirs[0];
}

export function selectInventory(options = {}, root = process.cwd()) {
  if (options.archive) {
    const archivePath = resolveArchivePath(options.archive, root);
    const inventoryRoot = extractArchive(archivePath);
    return { inventoryRoot, sourcePath: archivePath, sourceType: "archive", sourceName: path.basename(archivePath, ".tar.gz") };
  }
  if (options.inventoryDir) {
    const inventoryRoot = path.resolve(root, options.inventoryDir);
    return { inventoryRoot, sourcePath: inventoryRoot, sourceType: "directory", sourceName: path.basename(inventoryRoot) };
  }

  const archiveRoot = path.join(root, "artifacts", "aws-cleanup-inventory");
  const archives = readdirSync(archiveRoot)
    .filter((name) => /^\d{8}T\d{6}Z\.tar\.gz$/.test(name))
    .sort()
    .reverse();
  const inspected = [];
  for (const archiveName of archives) {
    const archivePath = path.join(archiveRoot, archiveName);
    const inventoryRoot = extractArchive(archivePath);
    const validation = validateInventory(inventoryRoot);
    inspected.push({ archivePath, validation });
    if (validation.complete) {
      return {
        inventoryRoot,
        sourcePath: archivePath,
        sourceType: "archive",
        sourceName: path.basename(archiveName, ".tar.gz"),
        inspectedArchives: inspected,
      };
    }
  }
  throw new Error(`No complete inventory archive found under ${archiveRoot}`);
}

function readJson(filePath) {
  return JSON.parse(readFileSync(filePath, "utf8"));
}

function readJsonOptional(root, relativePath, fallback = null) {
  const filePath = path.join(root, relativePath);
  if (!existsSync(filePath)) return fallback;
  return readJson(filePath);
}

function arrayFrom(data, keys = []) {
  if (!data) return [];
  if (Array.isArray(data)) return data;
  for (const key of keys) if (Array.isArray(data[key])) return data[key];
  const firstArray = Object.values(data).find(Array.isArray);
  return Array.isArray(firstArray) ? firstArray : [];
}

function regionFile(root, region, names) {
  for (const name of names) {
    const filePath = path.join(root, region, name);
    if (existsSync(filePath)) return filePath;
  }
  return "";
}

export function validateInventory(inventoryRoot) {
  const reasons = [];
  const validRegionPattern = /^[a-z]{2}-[a-z]+-\d$/;
  const topEntries = existsSync(inventoryRoot) ? readdirSync(inventoryRoot, { withFileTypes: true }) : [];
  for (const entry of topEntries) {
    if (entry.isDirectory() && entry.name.includes(" ") && entry.name.includes("ap-south-1")) {
      reasons.push(`broken region-loop directory detected: ${entry.name}`);
    }
  }

  for (const file of ["route53-mscqr-records.json", "route53-hosted-zones.json", "s3-buckets.json"]) {
    if (!existsSync(path.join(inventoryRoot, file))) reasons.push(`missing ${file}`);
  }
  if (!existsSync(path.join(inventoryRoot, "iam-roles-likely-mscqr.json")) && !existsSync(path.join(inventoryRoot, "iam-suspect-roles.json"))) {
    reasons.push("missing IAM roles inventory");
  }
  if (!existsSync(path.join(inventoryRoot, "iam-policies-likely-mscqr.json")) && !existsSync(path.join(inventoryRoot, "iam-suspect-policies.json"))) {
    reasons.push("missing IAM policies inventory");
  }

  for (const region of REQUIRED_REGIONS) {
    const regionDir = path.join(inventoryRoot, region);
    if (!existsSync(regionDir) || !statSync(regionDir).isDirectory()) {
      reasons.push(`missing region directory ${region}`);
      continue;
    }
    if (!validRegionPattern.test(region)) reasons.push(`invalid AWS region format: ${region}`);
    for (const names of REQUIRED_REGION_FILES) {
      const found = regionFile(inventoryRoot, region, names);
      if (!found) reasons.push(`missing ${region}/${names.join(" or ")}`);
      else {
        try {
          readJson(found);
        } catch (error) {
          reasons.push(`invalid JSON ${path.relative(inventoryRoot, found)}: ${error.message}`);
        }
      }
    }
  }

  try {
    const records = arrayFrom(readJson(path.join(inventoryRoot, "route53-mscqr-records.json")), ["ResourceRecordSets"]);
    if (records.length === 0) reasons.push("route53 records inventory is empty");
  } catch (error) {
    reasons.push(`invalid route53 records JSON: ${error.message}`);
  }
  try {
    const buckets = arrayFrom(readJson(path.join(inventoryRoot, "s3-buckets.json")), ["Buckets"]);
    if (buckets.length === 0) reasons.push("s3 buckets inventory is empty");
  } catch (error) {
    reasons.push(`invalid s3 buckets JSON: ${error.message}`);
  }

  return { complete: reasons.length === 0, reasons };
}

export function inspectAvailableInventories(root = process.cwd()) {
  const dir = path.join(root, "artifacts", "aws-cleanup-inventory");
  if (!existsSync(dir)) return [];
  return readdirSync(dir)
    .filter((name) => /^\d{8}T\d{6}Z\.tar\.gz$/.test(name))
    .sort()
    .map((name) => {
      const archivePath = path.join(dir, name);
      try {
        const inventoryRoot = extractArchive(archivePath);
        const validation = validateInventory(inventoryRoot);
        return { archivePath, complete: validation.complete, reasons: validation.reasons };
      } catch (error) {
        return { archivePath, complete: false, reasons: [error.message || String(error)] };
      }
    });
}

export function classifyInventory(inventoryRoot, metadata = {}) {
  const resources = [];
  const context = buildReferenceContext(inventoryRoot);

  addRoute53(resources, inventoryRoot);
  addS3(resources, inventoryRoot);
  addIam(resources, inventoryRoot);
  for (const region of REQUIRED_REGIONS) addRegional(resources, inventoryRoot, region, context);

  return {
    generatedAt: new Date().toISOString(),
    sourceInventoryPath: metadata.sourcePath || inventoryRoot,
    sourceType: metadata.sourceType || "directory",
    inventoryRoot,
    validation: validateInventory(inventoryRoot),
    resources,
    summary: summarize(resources),
  };
}

function buildReferenceContext(root) {
  const loadBalancerArns = new Set();
  const currentLoadBalancerArns = new Set();
  const asgTargetGroupArns = new Set();
  const attachedSecurityGroups = new Set();
  const targetHealth = new Map();

  for (const region of REQUIRED_REGIONS) {
    for (const lb of readRegionArray(root, region, ["load-balancers.json", "elbv2-load-balancers.json"], ["LoadBalancers"])) {
      if (lb.LoadBalancerArn) loadBalancerArns.add(lb.LoadBalancerArn);
      const dns = normalizeDns(lb.DNSName);
      if (CURRENT.albDnsNames.has(dns)) currentLoadBalancerArns.add(lb.LoadBalancerArn);
      for (const groupId of lb.SecurityGroups || []) attachedSecurityGroups.add(groupId);
    }
    for (const asg of readRegionArray(root, region, ["auto-scaling-groups.json"], ["AutoScalingGroups"])) {
      for (const arn of asg.TargetGroupARNs || []) asgTargetGroupArns.add(arn);
    }
    for (const eni of readRegionArray(root, region, ["network-interfaces.json"], ["NetworkInterfaces"])) {
      if (eni.Attachment?.Status === "attached") {
        for (const group of eni.Groups || []) if (group.GroupId) attachedSecurityGroups.add(group.GroupId);
      }
    }
    for (const db of readRegionArray(root, region, ["rds-db-instances.json"], ["DBInstances"])) {
      for (const group of db.VpcSecurityGroups || []) if (group.VpcSecurityGroupId) attachedSecurityGroups.add(group.VpcSecurityGroupId);
    }
    const healthPath = path.join(root, region, "elbv2-target-health.jsonl");
    if (existsSync(healthPath)) {
      for (const line of readFileSync(healthPath, "utf8").split("\n").filter(Boolean)) {
        try {
          const item = JSON.parse(line);
          const arn = item.TargetGroupArn || item.TargetGroupARN || item.targetGroupArn;
          const descriptions = item.TargetHealthDescriptions || item.Targets || item.targetHealthDescriptions || [];
          if (arn) targetHealth.set(arn, descriptions);
        } catch {
          // Keep classification conservative when target health evidence is malformed.
        }
      }
    }
  }
  return { loadBalancerArns, currentLoadBalancerArns, asgTargetGroupArns, attachedSecurityGroups, targetHealth };
}

function readRegionArray(root, region, fileNames, keys = []) {
  const filePath = regionFile(root, region, fileNames);
  if (!filePath) return [];
  return arrayFrom(readJson(filePath), keys);
}

function normalizeDns(value) {
  return String(value || "").replace(/\.$/, "").toLowerCase();
}

function tagValue(resource, key) {
  return (resource.Tags || []).find((tag) => tag.Key === key)?.Value || "";
}

function add(resources, input) {
  resources.push({
    classification: input.classification,
    service: input.service,
    region: input.region,
    resourceType: input.resourceType,
    resourceId: input.resourceId || "",
    resourceName: input.resourceName || "",
    arn: input.arn || "",
    evidence: input.evidence || [],
    risk: input.risk,
    consoleReviewRequired: input.consoleReviewRequired ?? input.classification !== CLASSIFICATIONS.KEEP,
    recommendedAction: input.recommendedAction,
    consoleReviewChecklist: consoleChecklist(input.service, input.region, input.resourceType, input.resourceId || input.resourceName),
    notes: input.notes || "",
  });
}

function addRoute53(resources, root) {
  for (const zone of arrayFrom(readJsonOptional(root, "route53-hosted-zones.json", {}), ["HostedZones"])) {
    const zoneId = String(zone.Id || "").split("/").pop();
    const isCurrent = zoneId === CURRENT.hostedZoneId || zone.Name === CURRENT.domainName;
    add(resources, base({
      classification: isCurrent ? CLASSIFICATIONS.KEEP : CLASSIFICATIONS.REVIEW_REQUIRED,
      service: "route53",
      region: "global",
      resourceType: "hosted-zone",
      resourceId: zoneId,
      resourceName: zone.Name,
      evidence: isCurrent ? ["Current MSCQR hosted zone."] : ["Hosted zone is not the known active MSCQR zone."],
      notes: isCurrent ? "Active production DNS zone." : "Ambiguous hosted zone; visual console review required.",
    }));
  }

  for (const record of arrayFrom(readJsonOptional(root, "route53-mscqr-records.json", {}), ["ResourceRecordSets"])) {
    const name = String(record.Name || "");
    const type = String(record.Type || "");
    const id = [name, type, record.SetIdentifier || ""].filter(Boolean).join(" ");
    const lowerName = name.toLowerCase();
    let classification = CLASSIFICATIONS.REVIEW_REQUIRED;
    const evidence = [];
    let notes = "DNS record is ambiguous; review before any future action.";

    const isApexGeo =
      lowerName === CURRENT.domainName &&
      type === "A" &&
      ["africa-capetown", "europe-london", "default-mumbai"].includes(record.SetIdentifier);
    if (isApexGeo) {
      classification = CLASSIFICATIONS.KEEP;
      evidence.push("Current Route 53 apex geolocation A record.");
      notes = "Current production DNS policy.";
    } else if (lowerName === "www.mscqr.com." && type === "CNAME") {
      classification = CLASSIFICATIONS.KEEP;
      evidence.push("Current www CNAME is explicitly protected.");
      notes = "Preserve public web hostname record.";
    } else if (["MX", "NS", "SOA", "TXT"].includes(type) || /(_dmarc|dkim|spf|amazonses|domainkey)/i.test(name)) {
      classification = CLASSIFICATIONS.KEEP;
      evidence.push("Email, ownership, or zone authority record is protected.");
      notes = "DMARC/DKIM/SPF/MX/NS/SOA/TXT records are not cleanup candidates.";
    } else if (type === "CNAME" && /^_[^.]+\.mscqr\.com\.$/i.test(name) && /acm-validations\.aws/i.test(JSON.stringify(record))) {
      classification = CLASSIFICATIONS.KEEP;
      evidence.push("ACM DNS validation CNAME for MSCQR certificate.");
      notes = "Preserve certificate validation while certs are active.";
    } else if (/^dr-(mumbai|capetown)\.mscqr\.com\.$/i.test(name)) {
      evidence.push("DR test hostname requires documentation review.");
      notes = "Hard rule: DR test records are REVIEW_REQUIRED unless docs prove active use.";
    } else {
      evidence.push("No hard KEEP rule matched.");
    }

    add(resources, base({
      classification,
      service: "route53",
      region: "global",
      resourceType: "record",
      resourceId: id,
      resourceName: name,
      evidence,
      notes,
    }));
  }
}

function addS3(resources, root) {
  for (const bucket of arrayFrom(readJsonOptional(root, "s3-buckets.json", {}), ["Buckets"])) {
    const name = bucket.Name || "";
    let classification = CLASSIFICATIONS.REVIEW_REQUIRED;
    const evidence = [];
    let notes = "S3 bucket requires owner review; buckets are not deletion candidates in this pass.";
    if (CURRENT.productionBuckets.has(name)) {
      classification = CLASSIFICATIONS.KEEP;
      evidence.push("Known production S3 artifact bucket.");
      notes = "Production object storage uses S3 default credentials.";
    } else if (CURRENT.albLogBuckets.has(name)) {
      classification = CLASSIFICATIONS.KEEP;
      evidence.push("Known ALB access log bucket that may be active.");
      notes = "Keep or review retention separately; do not delete in this pass.";
    } else if (/minio/i.test(name)) {
      evidence.push("MinIO-like bucket name; production MinIO is not expected.");
      notes = "REVIEW_REQUIRED unless proven local/dev only.";
    } else {
      evidence.push("Bucket is not in known production bucket allow-list.");
    }
    add(resources, base({
      classification,
      service: "s3",
      region: "global",
      resourceType: "bucket",
      resourceId: name,
      resourceName: name,
      arn: bucket.BucketArn || `arn:aws:s3:::${name}`,
      evidence,
      notes,
    }));
  }
}

function addIam(resources, root) {
  const roles = arrayFrom(
    readJsonOptional(root, "iam-roles-likely-mscqr.json", readJsonOptional(root, "iam-suspect-roles.json", [])),
  );
  const policies = arrayFrom(
    readJsonOptional(root, "iam-policies-likely-mscqr.json", readJsonOptional(root, "iam-suspect-policies.json", [])),
  );
  for (const role of roles) {
    const name = role.RoleName || "";
    const keep = CURRENT.keepIamRoles.has(name);
    add(resources, base({
      classification: keep ? CLASSIFICATIONS.KEEP : CLASSIFICATIONS.REVIEW_REQUIRED,
      service: "iam",
      region: "global",
      resourceType: "role",
      resourceId: name,
      resourceName: name,
      arn: role.Arn,
      evidence: keep ? ["Recognized current MSCQR production or GitHub role."] : ["IAM role is identity-critical and ambiguous."],
      notes: keep ? "Current production/GitHub operational role." : "Review trust policy, attachments, and last-used data before any future action.",
    }));
  }
  for (const policy of policies) {
    const name = policy.PolicyName || "";
    const keep = /^mscqr-ec2-s3-artifacts-policy-(aps1|afs1)$/.test(name) && Number(policy.AttachmentCount || 0) > 0;
    add(resources, base({
      classification: keep ? CLASSIFICATIONS.KEEP : CLASSIFICATIONS.REVIEW_REQUIRED,
      service: "iam",
      region: "global",
      resourceType: "policy",
      resourceId: name,
      resourceName: name,
      arn: policy.Arn,
      evidence: keep ? ["Attached regional production S3 artifact access policy."] : ["IAM policy requires attachment and usage review."],
      notes: keep ? "Current regional production object-storage access policy." : "IAM policies are not cleanup candidates without console verification.",
    }));
  }
}

function addRegional(resources, root, region, context) {
  for (const instance of readRegionArray(root, region, ["ec2-instances.json"], ["Reservations", "Instances"])) {
    const asg = tagValue(instance, "aws:autoscaling:groupName");
    const name = instance.Name || tagValue(instance, "Name");
    const keep = CURRENT.productionAsgs.has(asg) || CURRENT.productionInstanceNames.has(name);
    add(resources, base({
      classification: keep ? CLASSIFICATIONS.KEEP : CLASSIFICATIONS.REVIEW_REQUIRED,
      service: "ec2",
      region,
      resourceType: "instance",
      resourceId: instance.InstanceId,
      resourceName: name,
      arn: `arn:aws:ec2:${region}:368992683803:instance/${instance.InstanceId}`,
      evidence: keep ? ["Current production EC2/ASG/GitHub runner instance."] : ["EC2 instance not recognized as current production."],
      notes: keep ? "Running production or operational instance." : "Compute-like resource may be stoppable later only after console confirmation.",
    }));
  }

  for (const volume of readRegionArray(root, region, ["ebs-volumes.json"], ["Volumes"])) {
    const attached = (volume.Attachments || []).length > 0 || volume.State === "in-use";
    add(resources, base({
      classification: attached ? CLASSIFICATIONS.KEEP : CLASSIFICATIONS.REVIEW_REQUIRED,
      service: "ebs",
      region,
      resourceType: "volume",
      resourceId: volume.VolumeId,
      resourceName: volume.VolumeId,
      arn: `arn:aws:ec2:${region}:368992683803:volume/${volume.VolumeId}`,
      evidence: attached ? ["EBS volume is attached/in-use."] : ["EBS volume is unattached; hard rule requires REVIEW_REQUIRED."],
      notes: attached ? "Attached volumes are protected." : "Unattached EBS volumes are not auto-delete candidates.",
    }));
  }

  for (const snapshot of readRegionArray(root, region, ["ebs-snapshots.json"], ["Snapshots"])) {
    add(resources, base({
      classification: CLASSIFICATIONS.REVIEW_REQUIRED,
      service: "ebs",
      region,
      resourceType: "snapshot",
      resourceId: snapshot.SnapshotId,
      resourceName: snapshot.Description || snapshot.SnapshotId,
      arn: `arn:aws:ec2:${region}:368992683803:snapshot/${snapshot.SnapshotId}`,
      evidence: ["EBS snapshots require age, source, and restore-value review."],
      notes: "No EBS snapshot is automatically safe to remove in this pass.",
    }));
  }

  for (const eip of readRegionArray(root, region, ["elastic-ips.json"], ["Addresses"])) {
    const associated = Boolean(eip.AssociationId || eip.NetworkInterfaceId || eip.InstanceId || eip.ServiceManaged);
    add(resources, base({
      classification: associated ? CLASSIFICATIONS.KEEP : CLASSIFICATIONS.REVIEW_REQUIRED,
      service: "ec2",
      region,
      resourceType: "elastic-ip",
      resourceId: eip.AllocationId || eip.PublicIp,
      resourceName: eip.PublicIp,
      evidence: associated ? ["Elastic IP is associated or service-managed."] : ["Elastic IP is unassociated and needs console billing/ownership review."],
      notes: associated ? "Associated EIP is protected." : "Potential later release candidate only after visual confirmation.",
    }));
  }

  for (const lb of readRegionArray(root, region, ["load-balancers.json", "elbv2-load-balancers.json"], ["LoadBalancers"])) {
    const keep = CURRENT.albDnsNames.has(normalizeDns(lb.DNSName));
    add(resources, base({
      classification: keep ? CLASSIFICATIONS.KEEP : CLASSIFICATIONS.REVIEW_REQUIRED,
      service: "elbv2",
      region,
      resourceType: "load-balancer",
      resourceId: lb.LoadBalancerArn,
      resourceName: lb.LoadBalancerName,
      arn: lb.LoadBalancerArn,
      evidence: keep ? ["Current regional production ALB DNS name."] : ["Load balancer is not a known current production ALB."],
      notes: keep ? "Current DNS policy target." : "Review listeners, DNS references, and target groups.",
    }));
  }

  for (const tg of readRegionArray(root, region, ["target-groups.json", "elbv2-target-groups.json"], ["TargetGroups"])) {
    const attachedToLb = (tg.LoadBalancerArns || []).some((arn) => context.loadBalancerArns.has(arn));
    const attachedToCurrentLb = (tg.LoadBalancerArns || []).some((arn) => context.currentLoadBalancerArns.has(arn));
    const asgReferenced = context.asgTargetGroupArns.has(tg.TargetGroupArn);
    const targetHealth = context.targetHealth.get(tg.TargetGroupArn);
    const emptyHealth = Array.isArray(targetHealth) && targetHealth.length === 0;
    let classification = CLASSIFICATIONS.REVIEW_REQUIRED;
    const evidence = [];
    let notes = "Target group needs listener/ASG/target-health review.";
    if (attachedToCurrentLb || asgReferenced) {
      classification = CLASSIFICATIONS.KEEP;
      evidence.push("Target group is attached to current ALB or referenced by ASG.");
      notes = "Current production routing dependency.";
    } else if (!attachedToLb && emptyHealth) {
      classification = CLASSIFICATIONS.SAFE_TO_DELETE_LATER;
      evidence.push("No load balancer attachment, no ASG reference, and target-health evidence is empty.");
      notes = "Candidate only after visual AWS Console confirmation and separate approval.";
    } else {
      evidence.push("No current production attachment proven, or target-health evidence is missing.");
    }
    add(resources, base({
      classification,
      service: "elbv2",
      region,
      resourceType: "target-group",
      resourceId: tg.TargetGroupArn,
      resourceName: tg.TargetGroupName,
      arn: tg.TargetGroupArn,
      evidence,
      notes,
    }));
  }

  for (const asg of readRegionArray(root, region, ["auto-scaling-groups.json"], ["AutoScalingGroups"])) {
    const keep = CURRENT.productionAsgs.has(asg.AutoScalingGroupName);
    add(resources, base({
      classification: keep ? CLASSIFICATIONS.KEEP : CLASSIFICATIONS.REVIEW_REQUIRED,
      service: "autoscaling",
      region,
      resourceType: "auto-scaling-group",
      resourceId: asg.AutoScalingGroupName,
      resourceName: asg.AutoScalingGroupName,
      arn: asg.AutoScalingGroupARN,
      evidence: keep ? ["Current production regional ASG."] : ["ASG not recognized as current production."],
      notes: keep ? "Current regional DR/prod capacity." : "Review desired capacity, target groups, and launch template.",
    }));
  }

  for (const lt of readRegionArray(root, region, ["launch-templates.json"], ["LaunchTemplates"])) {
    const keep = /mscqr-(mumbai|capetown)-dr-lt/.test(lt.LaunchTemplateName || "");
    add(resources, base({
      classification: keep ? CLASSIFICATIONS.KEEP : CLASSIFICATIONS.REVIEW_REQUIRED,
      service: "launch-template",
      region,
      resourceType: "launch-template",
      resourceId: lt.LaunchTemplateId,
      resourceName: lt.LaunchTemplateName,
      evidence: keep ? ["Launch template belongs to current regional ASG standard."] : ["Launch template usage is ambiguous."],
      notes: keep ? "Current ASG launch template." : "Review ASG references before any action.",
    }));
  }

  for (const sg of readRegionArray(root, region, ["security-groups.json"], ["SecurityGroups"])) {
    const attached = context.attachedSecurityGroups.has(sg.GroupId);
    add(resources, base({
      classification: attached ? CLASSIFICATIONS.KEEP : CLASSIFICATIONS.REVIEW_REQUIRED,
      service: "security-group",
      region,
      resourceType: "security-group",
      resourceId: sg.GroupId,
      resourceName: sg.GroupName,
      arn: sg.SecurityGroupArn,
      evidence: attached ? ["Security group is attached to ENI, load balancer, RDS, or instance evidence."] : ["No attachment found in inventory; hard rule requires review."],
      notes: attached ? "Attached security groups are protected." : "Security group requires ENI/reference console review.",
    }));
  }

  for (const eni of readRegionArray(root, region, ["network-interfaces.json"], ["NetworkInterfaces"])) {
    const attached = eni.Attachment?.Status === "attached";
    add(resources, base({
      classification: attached ? CLASSIFICATIONS.KEEP : CLASSIFICATIONS.REVIEW_REQUIRED,
      service: "network-interface",
      region,
      resourceType: "network-interface",
      resourceId: eni.NetworkInterfaceId,
      resourceName: eni.Description || eni.NetworkInterfaceId,
      evidence: attached ? ["Network interface is attached."] : ["Network interface attachment is absent or unclear."],
      notes: attached ? "Attached ENI is protected." : "Review owner/service-managed status in console.",
    }));
  }

  for (const db of readRegionArray(root, region, ["rds-db-instances.json"], ["DBInstances"])) {
    add(resources, dataBearing({
      service: "rds",
      region,
      resourceType: "db-instance",
      resourceId: db.DBInstanceIdentifier,
      resourceName: db.DBInstanceIdentifier,
      arn: db.DBInstanceArn,
      evidence: ["RDS DB instance is data-bearing."],
      notes: "Never delete without backup/export/snapshot and explicit approval.",
    }));
  }
  for (const cluster of readRegionArray(root, region, ["rds-db-clusters.json"], ["DBClusters"])) {
    add(resources, dataBearing({
      service: "rds",
      region,
      resourceType: "db-cluster",
      resourceId: cluster.DBClusterIdentifier,
      resourceName: cluster.DBClusterIdentifier,
      arn: cluster.DBClusterArn,
      evidence: ["RDS/Aurora cluster is data-bearing."],
      notes: "Never delete without backup/export/snapshot and explicit approval.",
    }));
  }
  for (const snapshot of readRegionArray(root, region, ["rds-manual-snapshots.json"], ["DBSnapshots"])) {
    add(resources, dataBearing({
      service: "rds",
      region,
      resourceType: "manual-snapshot",
      resourceId: snapshot.DBSnapshotIdentifier,
      resourceName: snapshot.DBSnapshotIdentifier,
      arn: snapshot.DBSnapshotArn,
      evidence: ["RDS manual snapshot is backup/recovery evidence."],
      notes: "Never delete without retention review and explicit approval.",
    }));
  }

  for (const cluster of readRegionArray(root, region, ["ecs-clusters.json"], ["clusterArns", "clusters"])) {
    const arn = typeof cluster === "string" ? cluster : cluster.clusterArn || cluster.ClusterArn;
    const name = arn?.split("/").pop() || cluster.clusterName || cluster.ClusterName || "";
    add(resources, base({
      classification: CLASSIFICATIONS.REVIEW_REQUIRED,
      service: "ecs",
      region,
      resourceType: "cluster",
      resourceId: arn || name,
      resourceName: name,
      arn,
      evidence: ["ECS resources require workflow/runtime usage review."],
      notes: "Review whether ECS release workflows still use this resource.",
    }));
  }
  for (const repo of readRegionArray(root, region, ["ecr-repositories.json"], ["repositories"])) {
    add(resources, base({
      classification: CLASSIFICATIONS.REVIEW_REQUIRED,
      service: "ecr",
      region,
      resourceType: "repository",
      resourceId: repo.repositoryName,
      resourceName: repo.repositoryName,
      arn: repo.repositoryArn,
      evidence: ["ECR resources require workflow/image-retention review."],
      notes: "Do not remove images/repos without release history review.",
    }));
  }
  for (const cert of readRegionArray(root, region, ["acm-certificates.json"], ["CertificateSummaryList", "Certificates"])) {
    const inUse = cert.InUse === true || (cert.InUseBy || []).length > 0;
    add(resources, base({
      classification: inUse ? CLASSIFICATIONS.KEEP : CLASSIFICATIONS.REVIEW_REQUIRED,
      service: "acm",
      region,
      resourceType: "certificate",
      resourceId: cert.CertificateArn,
      resourceName: cert.DomainName,
      arn: cert.CertificateArn,
      evidence: inUse ? ["ACM certificate is marked in use."] : ["ACM certificate is unused or usage not proven."],
      notes: inUse ? "Certificate attached to active infrastructure." : "Review domain validation and listener use.",
    }));
  }
  for (const alarm of readRegionArray(root, region, ["cloudwatch-alarms.json"], ["MetricAlarms"])) {
    const current = /MSCQR|mscqr|mumbai|capetown|euw2|prod/i.test(alarm.AlarmName || "");
    add(resources, base({
      classification: current ? CLASSIFICATIONS.KEEP : CLASSIFICATIONS.REVIEW_REQUIRED,
      service: "cloudwatch",
      region,
      resourceType: "alarm",
      resourceId: alarm.AlarmName,
      resourceName: alarm.AlarmName,
      arn: alarm.AlarmArn,
      evidence: current ? ["Alarm name matches current MSCQR production/DR naming."] : ["Alarm purpose is ambiguous."],
      notes: current ? "Current operational alarm candidate." : "Review alarm metric and action targets.",
    }));
  }
}

function base(input) {
  const classification = input.classification || CLASSIFICATIONS.REVIEW_REQUIRED;
  const riskByClassification = {
    [CLASSIFICATIONS.KEEP]: "LOW",
    [CLASSIFICATIONS.REVIEW_REQUIRED]: "MEDIUM",
    [CLASSIFICATIONS.SAFE_TO_STOP]: "MEDIUM",
    [CLASSIFICATIONS.SAFE_TO_DELETE_LATER]: "HIGH",
    [CLASSIFICATIONS.NEVER_DELETE_WITHOUT_BACKUP]: "NEVER_DELETE_WITHOUT_BACKUP",
  };
  const actionByClassification = {
    [CLASSIFICATIONS.KEEP]: "keep",
    [CLASSIFICATIONS.REVIEW_REQUIRED]: "review",
    [CLASSIFICATIONS.SAFE_TO_STOP]: "stop-later",
    [CLASSIFICATIONS.SAFE_TO_DELETE_LATER]: "delete-later",
    [CLASSIFICATIONS.NEVER_DELETE_WITHOUT_BACKUP]: "backup-before-any-action",
  };
  return {
    ...input,
    classification,
    risk: input.risk || riskByClassification[classification],
    recommendedAction: input.recommendedAction || actionByClassification[classification],
  };
}

function dataBearing(input) {
  return base({ ...input, classification: CLASSIFICATIONS.NEVER_DELETE_WITHOUT_BACKUP });
}

function consoleChecklist(service, region, resourceType, resourceId) {
  const pathByService = {
    ec2: "AWS Console > EC2",
    ebs: "AWS Console > EC2 > Elastic Block Store",
    route53: "AWS Console > Route 53",
    s3: "AWS Console > S3",
    iam: "AWS Console > IAM",
    elbv2: "AWS Console > EC2 > Load Balancing",
    rds: "AWS Console > RDS",
    ecs: "AWS Console > ECS",
    ecr: "AWS Console > ECR",
    acm: "AWS Console > Certificate Manager",
    cloudwatch: "AWS Console > CloudWatch > Alarms",
    autoscaling: "AWS Console > EC2 > Auto Scaling Groups",
    "security-group": "AWS Console > EC2 > Security Groups",
    "network-interface": "AWS Console > EC2 > Network Interfaces",
    "launch-template": "AWS Console > EC2 > Launch Templates",
  };
  return [
    `Open ${pathByService[service] || "AWS Console"}.`,
    `Verify region ${region}.`,
    `Search for ${resourceType} ${resourceId || "<resource id>"}.`,
    "Verify no attachment, DNS reference, listener, ASG, IAM, data, or workflow dependency exists.",
    "Capture screenshot before any future deletion or stop action.",
  ];
}

export function summarize(resources) {
  const counts = Object.fromEntries(Object.values(CLASSIFICATIONS).map((key) => [key, 0]));
  for (const resource of resources) counts[resource.classification] = (counts[resource.classification] || 0) + 1;
  return { total: resources.length, counts };
}

function groupBy(items, keyFn) {
  const groups = new Map();
  for (const item of items) {
    const key = keyFn(item);
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(item);
  }
  return groups;
}

export function renderMarkdown(report) {
  const lines = [
    "# MSCQR AWS Legacy Cleanup Inventory Classification",
    "",
    `Source inventory path/archive: \`${report.sourceInventoryPath}\``,
    `Generated timestamp: \`${report.generatedAt}\``,
    "",
    "**Warning: no deletion, stop, detach, Route 53 change, IAM change, or AWS mutation was performed. This report is classification and operator review only.**",
    "",
    "## Summary Counts",
    "",
    `- Total resources classified: ${report.summary.total}`,
    ...Object.entries(report.summary.counts).map(([key, value]) => `- ${key}: ${value}`),
    "",
    "## Current Production KEEP Resources",
    "",
    ...resourceBullets(report.resources.filter((item) => item.classification === CLASSIFICATIONS.KEEP)),
    "",
    "## REVIEW_REQUIRED Resources",
    "",
    ...resourceBullets(report.resources.filter((item) => item.classification === CLASSIFICATIONS.REVIEW_REQUIRED)),
    "",
    "## SAFE_TO_STOP Candidates",
    "",
    ...resourceBullets(report.resources.filter((item) => item.classification === CLASSIFICATIONS.SAFE_TO_STOP)),
    "",
    "## SAFE_TO_DELETE_LATER Candidates",
    "",
    ...resourceBullets(report.resources.filter((item) => item.classification === CLASSIFICATIONS.SAFE_TO_DELETE_LATER)),
    "",
    "## NEVER_DELETE_WITHOUT_BACKUP Resources",
    "",
    ...resourceBullets(report.resources.filter((item) => item.classification === CLASSIFICATIONS.NEVER_DELETE_WITHOUT_BACKUP)),
    "",
    "## Per-Service Review Sections",
    "",
  ];
  for (const [service, items] of groupBy(report.resources, (item) => item.service)) {
    lines.push(`### ${service}`, "");
    lines.push(...resourceBullets(items), "");
  }
  lines.push(
    "## Console Click Paths",
    "",
    "- EC2 instances: AWS Console > EC2 > Instances.",
    "- EBS volumes: AWS Console > EC2 > Elastic Block Store > Volumes.",
    "- Snapshots: AWS Console > EC2 > Elastic Block Store > Snapshots.",
    "- Elastic IPs: AWS Console > EC2 > Network & Security > Elastic IPs.",
    "- Target groups: AWS Console > EC2 > Load Balancing > Target Groups.",
    "- Load balancers: AWS Console > EC2 > Load Balancing > Load Balancers.",
    "- Security groups: AWS Console > EC2 > Network & Security > Security Groups.",
    "- RDS: AWS Console > RDS > Databases and Snapshots.",
    "- S3: AWS Console > S3 > Buckets.",
    "- IAM: AWS Console > IAM > Roles or Policies.",
    "- ACM: AWS Console > Certificate Manager > Certificates.",
    "- Route 53: AWS Console > Route 53 > Hosted zones > mscqr.com.",
    "",
    "## Deletion Approval Protocol",
    "",
    "1. Review one resource at a time.",
    "2. Operator visually confirms the resource in AWS Console.",
    "3. Screenshot/evidence is captured before any future action.",
    "4. Capture screenshot before any future deletion or stop action.",
    "5. A separate approval ledger is filled with resource ID, region, owner, evidence path, and approver.",
    "6. Terminal action is run only after separate approval in a future pass.",
    "7. Post-action inventory confirms the resource state changed as expected.",
    "",
    "## Resources Not Eligible For Deletion In This Pass",
    "",
    "- Route 53 apex geolocation records, www CNAME, MX, NS, SOA, TXT, DMARC, DKIM, SPF, and ACM validation records.",
    "- Current Mumbai, Cape Town, and London ALBs and attached target groups.",
    "- Current production ASGs, EC2 instances, GitHub runner instance, attached ENIs, attached security groups, and attached EBS volumes.",
    "- RDS/Aurora instances, clusters, and snapshots without backup/export/snapshot review and explicit approval.",
    "- Production S3 artifact buckets and ALB log buckets.",
    "- Current GitHub deploy and auto-failover read-only IAM roles.",
    "- Any ambiguous resource; ambiguity remains REVIEW_REQUIRED.",
    "",
  );
  return `${lines.join("\n")}\n`;
}

function resourceBullets(items) {
  if (items.length === 0) return ["- None."];
  return items.map((item) => {
    const name = item.resourceName && item.resourceName !== item.resourceId ? ` (${item.resourceName})` : "";
    return `- **${item.classification}** ${item.service}/${item.region}/${item.resourceType}: \`${item.resourceId}\`${name} - ${item.notes}`;
  });
}

export function renderSummary(report, inventoryInspections = []) {
  const lines = [
    `source=${report.sourceInventoryPath}`,
    `generatedAt=${report.generatedAt}`,
    `total=${report.summary.total}`,
    ...Object.entries(report.summary.counts).map(([key, value]) => `${key}=${value}`),
    "",
    "safe_to_stop:",
    ...plainList(report.resources.filter((item) => item.classification === CLASSIFICATIONS.SAFE_TO_STOP)),
    "",
    "safe_to_delete_later:",
    ...plainList(report.resources.filter((item) => item.classification === CLASSIFICATIONS.SAFE_TO_DELETE_LATER)),
    "",
    "never_delete_without_backup:",
    ...plainList(report.resources.filter((item) => item.classification === CLASSIFICATIONS.NEVER_DELETE_WITHOUT_BACKUP)),
    "",
    "review_required_by_service_region:",
  ];
  const review = report.resources.filter((item) => item.classification === CLASSIFICATIONS.REVIEW_REQUIRED);
  for (const [key, items] of groupBy(review, (item) => `${item.service}/${item.region}`)) {
    lines.push(`${key}: ${items.length}`);
    for (const item of items.slice(0, 20)) lines.push(`  - ${item.resourceType} ${item.resourceId} ${item.resourceName}`.trim());
  }
  if (inventoryInspections.length) {
    lines.push("", "inventory_validation:");
    for (const item of inventoryInspections) {
      lines.push(`- ${path.basename(item.archivePath)} complete=${item.complete} reasons=${item.reasons.join("; ") || "none"}`);
    }
  }
  return `${lines.join("\n")}\n`;
}

function plainList(items) {
  return items.length ? items.map((item) => `- ${item.service}/${item.region}/${item.resourceType} ${item.resourceId} ${item.resourceName}`.trim()) : ["- None"];
}

function outputDirFor(selection) {
  if (selection.sourceName && /^\d{8}T\d{6}Z$/.test(selection.sourceName)) {
    return path.join(process.cwd(), "artifacts", "aws-cleanup-inventory", selection.sourceName);
  }
  const hash = createHash("sha256").update(selection.sourcePath || selection.inventoryRoot).digest("hex").slice(0, 10);
  return path.join(process.cwd(), "artifacts", "aws-cleanup-inventory", `classified-${hash}`);
}

export function writeReports(report, selection, inspections = []) {
  const outDir = outputDirFor(selection);
  mkdirSync(outDir, { recursive: true });
  const jsonPath = path.join(outDir, "classified-resources.json");
  const mdPath = path.join(outDir, "classified-resources.md");
  const summaryPath = path.join(outDir, "classification-summary.txt");
  writeFileSync(jsonPath, `${JSON.stringify(report, null, 2)}\n`);
  writeFileSync(mdPath, renderMarkdown(report));
  writeFileSync(summaryPath, renderSummary(report, inspections));
  return { outDir, jsonPath, mdPath, summaryPath };
}

function printTerminalSummary(report, inspections, paths) {
  console.log("MSCQR AWS legacy cleanup inventory classification complete.");
  console.log(`Selected source: ${report.sourceInventoryPath}`);
  console.log(`Total resources classified: ${report.summary.total}`);
  for (const [key, value] of Object.entries(report.summary.counts)) console.log(`${key}: ${value}`);
  console.log(`classified-resources.json: ${paths.jsonPath}`);
  console.log(`classified-resources.md: ${paths.mdPath}`);
  console.log(`classification-summary.txt: ${paths.summaryPath}`);
  for (const item of inspections) {
    console.log(`inventory ${path.basename(item.archivePath)} complete=${item.complete} ${item.reasons.length ? item.reasons.join("; ") : "valid"}`);
  }
  for (const bucket of [
    CLASSIFICATIONS.SAFE_TO_STOP,
    CLASSIFICATIONS.SAFE_TO_DELETE_LATER,
    CLASSIFICATIONS.NEVER_DELETE_WITHOUT_BACKUP,
  ]) {
    console.log(`${bucket}:`);
    for (const line of plainList(report.resources.filter((item) => item.classification === bucket))) console.log(line);
  }
  console.log("REVIEW_REQUIRED grouped by service/region:");
  for (const [key, items] of groupBy(
    report.resources.filter((item) => item.classification === CLASSIFICATIONS.REVIEW_REQUIRED),
    (item) => `${item.service}/${item.region}`,
  )) {
    console.log(`- ${key}: ${items.length}`);
  }
}

export async function main() {
  const options = parseArgs(process.argv.slice(2));
  const inspections = inspectAvailableInventories();
  const selection = selectInventory(options);
  const validation = validateInventory(selection.inventoryRoot);
  if (!validation.complete) {
    console.error(`Inventory is incomplete: ${selection.sourcePath}`);
    for (const reason of validation.reasons) console.error(`- ${reason}`);
    process.exit(3);
  }
  const report = classifyInventory(selection.inventoryRoot, selection);
  const paths = writeReports(report, selection, inspections);
  printTerminalSummary(report, inspections, paths);
}

if (import.meta.url === pathToFileURL(process.argv[1] || "").href) {
  try {
    await main();
  } catch (error) {
    console.error(error.message || String(error));
    process.exit(2);
  }
}
