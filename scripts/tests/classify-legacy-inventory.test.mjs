import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import {
  CLASSIFICATIONS,
  classifyInventory,
  renderMarkdown,
  validateInventory,
} from "../aws/classify-legacy-inventory.mjs";

const requiredRegions = ["ap-south-1", "af-south-1", "eu-west-2", "us-east-1"];
const requiredFiles = [
  "ec2-instances.json",
  "ebs-volumes.json",
  "ebs-snapshots.json",
  "elastic-ips.json",
  "load-balancers.json",
  "target-groups.json",
  "auto-scaling-groups.json",
  "launch-templates.json",
  "security-groups.json",
  "network-interfaces.json",
  "rds-db-instances.json",
  "rds-db-clusters.json",
  "rds-manual-snapshots.json",
  "ecs-clusters.json",
  "ecr-repositories.json",
  "acm-certificates.json",
  "cloudwatch-alarms.json",
];

function writeJson(filePath, value) {
  writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`);
}

function fixture() {
  const root = mkdtempSync(path.join(tmpdir(), "mscqr-classifier-"));
  writeJson(path.join(root, "route53-hosted-zones.json"), {
    HostedZones: [{ Id: "/hostedzone/Z0569586VLFIGGVI7HAZ", Name: "mscqr.com." }],
  });
  writeJson(path.join(root, "route53-mscqr-records.json"), {
    ResourceRecordSets: [
      {
        Name: "mscqr.com.",
        Type: "A",
        SetIdentifier: "africa-capetown",
        GeoLocation: { ContinentCode: "AF" },
        AliasTarget: { DNSName: "mscqr-capetown-alb-1730011881.af-south-1.elb.amazonaws.com." },
      },
      { Name: "www.mscqr.com.", Type: "CNAME", ResourceRecords: [{ Value: "mscqr.com" }] },
      { Name: "mscqr.com.", Type: "MX", ResourceRecords: [{ Value: "10 mx.example.test" }] },
      { Name: "mscqr.com.", Type: "NS", ResourceRecords: [{ Value: "ns.example.test" }] },
      { Name: "mscqr.com.", Type: "SOA", ResourceRecords: [{ Value: "ns.example.test hostmaster.example.test 1 2 3 4 5" }] },
      { Name: "mscqr.com.", Type: "TXT", ResourceRecords: [{ Value: "v=spf1 include:example.test ~all" }] },
      { Name: "_dmarc.mscqr.com.", Type: "TXT", ResourceRecords: [{ Value: "v=DMARC1; p=none" }] },
    ],
  });
  writeJson(path.join(root, "s3-buckets.json"), {
    Buckets: [{ Name: "mscqr-prod-aps1-artifacts-368992683803-ap-south-1" }],
  });
  writeJson(path.join(root, "iam-roles-likely-mscqr.json"), [
    { RoleName: "mscqr-github-auto-failover-readonly", Arn: "arn:aws:iam::368992683803:role/mscqr-github-auto-failover-readonly" },
    { RoleName: "old-mscqr-role", Arn: "arn:aws:iam::368992683803:role/old-mscqr-role" },
  ]);
  writeJson(path.join(root, "iam-policies-likely-mscqr.json"), []);

  for (const region of requiredRegions) {
    mkdirSync(path.join(root, region));
    for (const file of requiredFiles) writeJson(path.join(root, region, file), []);
    writeJson(path.join(root, region, "network-interfaces.json"), []);
    writeJson(path.join(root, region, "security-groups.json"), []);
  }

  writeJson(path.join(root, "ap-south-1", "load-balancers.json"), [
    {
      LoadBalancerArn: "arn:aws:elasticloadbalancing:ap-south-1:368992683803:loadbalancer/app/mscqr-mumbai-alb/1",
      LoadBalancerName: "mscqr-mumbai-alb",
      DNSName: "mscqr-mumbai-alb-1249752376.ap-south-1.elb.amazonaws.com",
      SecurityGroups: ["sg-attached"],
    },
  ]);
  writeJson(path.join(root, "ap-south-1", "target-groups.json"), [
    {
      TargetGroupArn: "arn:aws:elasticloadbalancing:ap-south-1:368992683803:targetgroup/current/1",
      TargetGroupName: "current",
      LoadBalancerArns: ["arn:aws:elasticloadbalancing:ap-south-1:368992683803:loadbalancer/app/mscqr-mumbai-alb/1"],
    },
    {
      TargetGroupArn: "arn:aws:elasticloadbalancing:ap-south-1:368992683803:targetgroup/orphan/1",
      TargetGroupName: "orphan",
      LoadBalancerArns: [],
    },
  ]);
  writeFileSync(
    path.join(root, "ap-south-1", "elbv2-target-health.jsonl"),
    `${JSON.stringify({
      TargetGroupArn: "arn:aws:elasticloadbalancing:ap-south-1:368992683803:targetgroup/orphan/1",
      TargetHealthDescriptions: [],
    })}\n`,
  );
  writeJson(path.join(root, "ap-south-1", "ebs-volumes.json"), [
    { VolumeId: "vol-attached", State: "in-use", Attachments: [{ InstanceId: "i-prod" }] },
    { VolumeId: "vol-unattached", State: "available", Attachments: [] },
  ]);
  writeJson(path.join(root, "ap-south-1", "rds-db-instances.json"), [{ DBInstanceIdentifier: "mscqr-prod-db-aps1" }]);
  writeJson(path.join(root, "ap-south-1", "rds-db-clusters.json"), [{ DBClusterIdentifier: "mscqr-prod-cluster" }]);
  writeJson(path.join(root, "ap-south-1", "rds-manual-snapshots.json"), [{ DBSnapshotIdentifier: "manual-snapshot" }]);
  return root;
}

function byId(resources, id) {
  return resources.find((resource) => resource.resourceId === id || resource.resourceName === id);
}

test("broken region-loop inventory is detected as incomplete", () => {
  const root = mkdtempSync(path.join(tmpdir(), "mscqr-broken-inventory-"));
  mkdirSync(path.join(root, "ap-south-1 af-south-1 eu-west-2 us-east-1"));
  writeJson(path.join(root, "route53-mscqr-records.json"), { ResourceRecordSets: [] });
  writeJson(path.join(root, "route53-hosted-zones.json"), { HostedZones: [] });
  writeJson(path.join(root, "s3-buckets.json"), { Buckets: [] });
  writeJson(path.join(root, "iam-suspect-roles.json"), []);
  writeJson(path.join(root, "iam-suspect-policies.json"), []);

  const result = validateInventory(root);
  assert.equal(result.complete, false);
  assert.match(result.reasons.join("\n"), /broken region-loop directory/);
  assert.match(result.reasons.join("\n"), /missing region directory ap-south-1/);
});

test("hard classification rules are applied", () => {
  const report = classifyInventory(fixture());
  const resources = report.resources;

  assert.equal(byId(resources, "mscqr.com. A africa-capetown").classification, CLASSIFICATIONS.KEEP);
  for (const id of ["mscqr.com. MX", "mscqr.com. NS", "mscqr.com. SOA", "mscqr.com. TXT", "_dmarc.mscqr.com. TXT"]) {
    assert.equal(byId(resources, id).classification, CLASSIFICATIONS.KEEP);
  }
  assert.equal(byId(resources, "mscqr-mumbai-alb").classification, CLASSIFICATIONS.KEEP);
  assert.equal(byId(resources, "vol-attached").classification, CLASSIFICATIONS.KEEP);
  assert.equal(byId(resources, "vol-unattached").classification, CLASSIFICATIONS.REVIEW_REQUIRED);
  assert.equal(byId(resources, "mscqr-prod-db-aps1").classification, CLASSIFICATIONS.NEVER_DELETE_WITHOUT_BACKUP);
  assert.equal(byId(resources, "mscqr-prod-cluster").classification, CLASSIFICATIONS.NEVER_DELETE_WITHOUT_BACKUP);
  assert.equal(byId(resources, "manual-snapshot").classification, CLASSIFICATIONS.NEVER_DELETE_WITHOUT_BACKUP);
  assert.equal(byId(resources, "old-mscqr-role").classification, CLASSIFICATIONS.REVIEW_REQUIRED);
  assert.equal(byId(resources, "mscqr-github-auto-failover-readonly").classification, CLASSIFICATIONS.KEEP);

  const orphan = byId(resources, "orphan");
  assert([CLASSIFICATIONS.REVIEW_REQUIRED, CLASSIFICATIONS.SAFE_TO_DELETE_LATER].includes(orphan.classification));
  assert.equal(orphan.classification, CLASSIFICATIONS.SAFE_TO_DELETE_LATER);
});

test("classifier source contains no AWS mutation commands", () => {
  const source = readFileSync(new URL("../aws/classify-legacy-inventory.mjs", import.meta.url), "utf8");
  const forbidden = [
    /change-resource-record-sets/i,
    /terminate-instances/i,
    /stop-instances/i,
    /delete-volume/i,
    /delete-snapshot/i,
    /release-address/i,
    /delete-load-balancer/i,
    /delete-target-group/i,
    /delete-db-instance/i,
    /delete-db-cluster/i,
    /delete-bucket/i,
    /delete-role/i,
    /delete-policy/i,
    /detach-role-policy/i,
    /delete-certificate/i,
  ];
  for (const pattern of forbidden) assert.doesNotMatch(source, pattern);
});

test("generated markdown includes visual console confirmation protocol", () => {
  const report = classifyInventory(fixture());
  const markdown = renderMarkdown(report);

  assert.match(markdown, /MSCQR AWS Legacy Cleanup Inventory Classification/);
  assert.match(markdown, /no deletion, stop, detach, Route 53 change, IAM change, or AWS mutation was performed/);
  assert.match(markdown, /Console Click Paths/);
  assert.match(markdown, /Deletion Approval Protocol/);
  assert.match(markdown, /Operator visually confirms the resource in AWS Console/);
  assert.match(markdown, /Capture screenshot before any future deletion or stop action/);
});
