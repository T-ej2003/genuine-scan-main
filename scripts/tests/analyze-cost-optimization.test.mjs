import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { test } from "node:test";

import {
  ACTION_CATEGORIES,
  analyzeCostOptimization,
  parseUsageTypeCost,
} from "../aws/analyze-cost-optimization.mjs";

function fixtureRoot(name) {
  return path.join(tmpdir(), `mscqr-cost-${name}-${Date.now()}-${Math.random().toString(16).slice(2)}`);
}

function writeJson(filePath, value) {
  mkdirSync(path.dirname(filePath), { recursive: true });
  writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`);
}

function usageTypeReport(entries) {
  return {
    GroupDefinitions: [{ Type: "DIMENSION", Key: "USAGE_TYPE" }],
    ResultsByTime: [
      {
        Groups: entries.map(([usageType, amount, quantity = 24, unit = "Hrs"]) => ({
          Keys: [usageType],
          Metrics: {
            UnblendedCost: { Amount: String(amount), Unit: "USD" },
            UsageQuantity: { Amount: String(quantity), Unit: unit },
          },
        })),
      },
    ],
  };
}

function makeDeepDiveFixture() {
  const root = fixtureRoot("deep-dive");
  const evidenceDir = path.join(root, "MSCQR-AWS-Cost-Deep-Dive-20260603T121634Z");
  const screenshotsDir = path.join(root, "screenshots");
  mkdirSync(evidenceDir, { recursive: true });
  mkdirSync(screenshotsDir, { recursive: true });
  writeFileSync(path.join(evidenceDir, "00-identity.txt"), "account 368992683803\n");
  writeFileSync(path.join(screenshotsDir, "14-rds-cost-usage-type.png"), "not really a png but local evidence path is enough\n");
  writeFileSync(
    path.join(evidenceDir, "costs.csv"),
    '"Service","Relational Database Service($)","ElastiCache($)","Tax($)","EC2-Instances($)","EC2-Other($)","Elastic Load Balancing($)","VPC($)","Total costs($)"\n"Service total","499.57","344.17","246.03","168.25","102.94","46.32","41.27","1476.19"\n',
  );
  writeJson(path.join(evidenceDir, "10-cost-rds-usage-type.json"), usageTypeReport([
    ["AFS1-Multi-AZUsage:db.m5d.large", 284.16],
    ["APS3-InstanceUsage:db.m5.large", 135.98],
  ]));
  writeJson(path.join(evidenceDir, "11-cost-elasticache-usage-type.json"), usageTypeReport([
    ["EUW2-NodeUsage:cache.r7g.large", 186.37],
    ["APS3-NodeUsage:cache.t4g.medium", 58.97],
  ]));
  writeJson(path.join(evidenceDir, "12-cost-ec2-other-usage-type.json"), usageTypeReport([
    ["EUW2-NatGateway-Hours", 60],
    ["AFS1-EBS:VolumeUsage.gp2", 5],
  ]));
  writeJson(path.join(evidenceDir, "13-cost-vpc-usage-type.json"), usageTypeReport([
    ["EUW2-PublicIPv4:InUseAddress", 18.62],
    ["APS3-PublicIPv4:InUseAddress", 13.73],
  ]));

  writeJson(path.join(evidenceDir, "ap-south-1", "rds-db-instances.json"), {
    DBInstances: [{
      AllocatedStorage: 20,
      BackupRetentionPeriod: 7,
      DBInstanceClass: "db.t4g.medium",
      DBInstanceIdentifier: "mscqr-prod-db-aps1",
      DBInstanceStatus: "available",
      Engine: "postgres",
      MultiAZ: false,
      Region: "ap-south-1",
      StorageType: "gp3",
    }],
  });
  writeJson(path.join(evidenceDir, "ap-south-1", "rds-manual-snapshots.json"), {
    DBSnapshots: [{
      DBInstanceIdentifier: "mscqr-prod-db-aps1",
      DBSnapshotIdentifier: "mscqr-prod-db-aps1-manual-2026-04-27",
      SnapshotCreateTime: "2026-04-27T19:05:25.729000Z",
      SnapshotType: "manual",
      Status: "available",
    }],
  });
  writeJson(path.join(evidenceDir, "ap-south-1", "elasticache-cache-clusters.json"), {
    CacheClusters: [{
      CacheClusterId: "mscqr-redis-aps1-primary-001",
      CacheClusterStatus: "available",
      CacheNodeType: "cache.t4g.medium",
      Engine: "valkey",
      NumCacheNodes: 1,
      PreferredAvailabilityZone: "ap-south-1a",
      ReplicationGroupId: "mscqr-redis-aps1-primary",
    }],
  });
  writeJson(path.join(evidenceDir, "eu-west-2", "nat-gateways.json"), {
    NatGateways: [{
      NatGatewayAddresses: [{ PublicIp: "35.179.203.86" }],
      NatGatewayId: "nat-123",
      State: "available",
      SubnetId: "subnet-123",
      Tags: [{ Key: "Name", Value: "mscqr-prod-euw2-nat" }],
      VpcId: "vpc-123",
    }],
  });
  writeJson(path.join(evidenceDir, "ap-south-1", "ec2-instances.json"), {
    Reservations: [{
      Instances: [{
        IamInstanceProfile: { Arn: "arn:aws:iam::368992683803:instance-profile/mscqr-asg-web-instance-profile-aps1" },
        InstanceId: "i-prod",
        InstanceType: "t3.medium",
        LaunchTime: "2026-06-01T00:00:00Z",
        State: { Name: "running" },
        Tags: [{ Key: "Name", Value: "mscqr-prod-mumbai" }],
      }],
    }],
  });
  writeJson(path.join(evidenceDir, "ap-south-1", "ebs-volumes.json"), {
    Volumes: [{
      Attachments: [],
      Encrypted: true,
      Size: 10,
      State: "available",
      VolumeId: "vol-unused",
      VolumeType: "gp3",
    }],
  });
  writeJson(path.join(evidenceDir, "ap-south-1", "ebs-snapshots.json"), { Snapshots: [] });

  for (const region of ["af-south-1", "eu-west-2", "us-east-1"]) {
    for (const name of ["rds-db-instances", "rds-manual-snapshots", "elasticache-cache-clusters", "nat-gateways", "ec2-instances", "ebs-volumes", "ebs-snapshots"]) {
      const key = {
        "rds-db-instances": "DBInstances",
        "rds-manual-snapshots": "DBSnapshots",
        "elasticache-cache-clusters": "CacheClusters",
        "nat-gateways": "NatGateways",
        "ec2-instances": "Reservations",
        "ebs-volumes": "Volumes",
        "ebs-snapshots": "Snapshots",
      }[name];
      const file = path.join(evidenceDir, region, `${name}.json`);
      if (!existsSync(file)) writeJson(file, { [key]: [] });
    }
  }

  writeJson(path.join(root, "artifacts", "aws-cleanup-inventory", "20260603T103903Z", "classified-resources.json"), {
    resources: [
      {
        classification: "KEEP",
        evidence: ["Production apex geolocation record."],
        region: "global",
        resourceId: "mscqr.com. A default",
        resourceName: "mscqr.com.",
        resourceType: "record",
        service: "route53",
      },
    ],
  });

  return { evidenceDir, root, screenshotsDir };
}

test("deep-dive archive detection extracts and analyzes local evidence", () => {
  const { evidenceDir, root, screenshotsDir } = makeDeepDiveFixture();
  const archive = path.join(root, "deep-dive.tar.gz");
  execFileSync("/usr/bin/tar", ["-czf", archive, "-C", path.dirname(evidenceDir), path.basename(evidenceDir)]);

  const result = analyzeCostOptimization({
    archive,
    downloadsRoot: path.join(root, "downloads"),
    outputRoot: path.join(root, "reports"),
    screenshotsDir,
    timestamp: "20260603T130000Z",
  }, root);

  assert.equal(result.evidence.sourceType, "archive");
  assert.match(result.evidence.selectedEvidenceDir, /mscqr-cost-evidence/u);
  assert.ok(result.candidates.some((candidate) => candidate.service === "RDS"));
});

test("usage-type cost parsing captures dominant cost lines", () => {
  const { evidenceDir } = makeDeepDiveFixture();
  const parsed = parseUsageTypeCost(path.join(evidenceDir, "10-cost-rds-usage-type.json"));
  assert.equal(parsed.total, 420.14);
  assert.equal(parsed.usageTypes[0].usageType, "AFS1-Multi-AZUsage:db.m5d.large");
});

test("RDS, ElastiCache, and NAT classifications are conservative", () => {
  const { evidenceDir, root, screenshotsDir } = makeDeepDiveFixture();
  const result = analyzeCostOptimization({
    evidenceDir,
    downloadsRoot: path.join(root, "downloads"),
    outputRoot: path.join(root, "reports"),
    screenshotsDir,
    timestamp: "20260603T130001Z",
  }, root);

  const rds = result.candidates.find((candidate) => candidate.service === "RDS" && candidate.resourceType === "DB instance");
  const snapshot = result.candidates.find((candidate) => candidate.resourceType === "RDS manual snapshot");
  const cache = result.candidates.find((candidate) => candidate.service === "ElastiCache");
  const nat = result.candidates.find((candidate) => candidate.service === "VPC");

  assert.equal(rds.actionCategory, ACTION_CATEGORIES.CANDIDATE_RIGHTSIZE_AFTER_METRICS);
  assert.equal(snapshot.actionCategory, ACTION_CATEGORIES.NEVER_DELETE_WITHOUT_BACKUP);
  assert.equal(cache.actionCategory, ACTION_CATEGORIES.CANDIDATE_RIGHTSIZE_AFTER_METRICS);
  assert.equal(nat.actionCategory, ACTION_CATEGORIES.REVIEW_REQUIRED);
});

test("reports include Downloads path, checksums, action register, and console protocol", () => {
  const { evidenceDir, root, screenshotsDir } = makeDeepDiveFixture();
  const result = analyzeCostOptimization({
    evidenceDir,
    downloadsRoot: path.join(root, "downloads"),
    outputRoot: path.join(root, "reports"),
    screenshotsDir,
    timestamp: "20260603T130002Z",
  }, root);

  const markdown = readFileSync(result.outputs.markdown, "utf8");
  assert.match(markdown, /Download path/u);
  assert.match(markdown, /visual AWS Console confirmation|Console click-by-click review/u);
  assert.ok(existsSync(path.join(result.downloadsDir, "SHA256SUMS.txt")));
  assert.ok(existsSync(path.join(result.downloadsDir, "cost-action-register.tsv")));
  assert.ok(existsSync(path.join(result.downloadsDir, "proposed-console-review-checklist.md")));
});

test("Route 53 production records are never marked deletion-safe", () => {
  const { evidenceDir, root, screenshotsDir } = makeDeepDiveFixture();
  const result = analyzeCostOptimization({
    evidenceDir,
    downloadsRoot: path.join(root, "downloads"),
    outputRoot: path.join(root, "reports"),
    screenshotsDir,
    timestamp: "20260603T130003Z",
  }, root);

  const route53 = result.candidates.find((candidate) => candidate.service === "Route 53");
  assert.equal(route53.actionCategory, ACTION_CATEGORIES.KEEP);
  assert.notEqual(route53.actionCategory, ACTION_CATEGORIES.CANDIDATE_DELETE_AFTER_BACKUP_AND_APPROVAL);
});

test("analyzer source contains no executable AWS mutation commands", () => {
  const source = readFileSync(path.resolve("scripts/aws/analyze-cost-optimization.mjs"), "utf8");
  const blocked = [
    /\baws\s+route53\s+change-resource-record-sets\b/u,
    /\baws\s+rds\s+(?:delete|stop|modify)-/u,
    /\baws\s+elasticache\s+(?:delete|modify)-/u,
    /\baws\s+ec2\s+(?:terminate|stop)-/u,
    /\baws\s+elbv2\s+(?:delete|modify)-/u,
    /\baws\s+s3\s+rb\b/u,
    /\baws\s+s3api\s+delete-bucket\b/u,
    /\baws\s+iam\s+(?:delete|detach)-/u,
  ];
  for (const pattern of blocked) assert.doesNotMatch(source, pattern);
});
