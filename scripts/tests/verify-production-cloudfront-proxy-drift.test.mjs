import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import { verifyProductionCloudFrontProxyDrift } from "../aws/verify-production-cloudfront-proxy-drift.mjs";

const run = (drift = {}) => (args) => {
  const operation = `${args[0]} ${args[1]}`;
  if (operation === "ecs describe-services") return JSON.stringify({ services: [{ taskDefinition: "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-backend-candidate:1" }] });
  if (operation === "ecs describe-task-definition") return JSON.stringify({ taskDefinition: { containerDefinitions: [{ name: "backend", environment: [
    { name: "CLIENT_IP_TRUST_MODE", value: "cloudfront-alb" }, { name: "CLIENT_IP_TRUSTED_ALB_CIDRS", value: "10.1.0.0/24,10.1.1.0/24" }, { name: "CLIENT_IP_TRUSTED_CLOUDFRONT_CIDRS", value: drift.cidr ? "198.51.101.0/24" : "198.51.100.0/24" }, { name: "MSCQR_CLIENT_IP_CLOUDFRONT_PREFIX_LIST_ID", value: "pl-0123456789abcdef0" }, { name: "MSCQR_CLIENT_IP_CLOUDFRONT_PREFIX_LIST_VERSION", value: drift.version ? "8" : "7" },
  ] }] } });
  if (operation === "elbv2 describe-load-balancers") return JSON.stringify({ LoadBalancers: [{ LoadBalancerArn: "arn:aws:elasticloadbalancing:eu-west-2:368992683803:loadbalancer/app/mscqr-alb-euw2/example", DNSName: "mscqr-alb.example.elb.amazonaws.com", Type: "application", Scheme: "internet-facing", VpcId: "vpc-1", AvailabilityZones: [{ SubnetId: "subnet-a" }, { SubnetId: "subnet-b" }] }] });
  if (operation === "elbv2 describe-load-balancer-attributes") {
    if (drift.attributesUnavailable) return JSON.stringify({});
    return JSON.stringify({ Attributes: [{ Key: "routing.http.xff_header_processing.mode", Value: drift.xffMode || "append" }, { Key: "routing.http.xff_client_port.enabled", Value: drift.clientPort ? "true" : "false" }] });
  }
  if (operation === "elbv2 describe-target-groups") return JSON.stringify({ TargetGroups: [{ TargetGroupArn: "arn:aws:elasticloadbalancing:eu-west-2:368992683803:targetgroup/mscqr-backend-tg-euw2-v2/example", VpcId: "vpc-1", TargetType: "ip", Protocol: "HTTP", Port: 4000, HealthCheckPath: "/health/live", LoadBalancerArns: ["arn:aws:elasticloadbalancing:eu-west-2:368992683803:loadbalancer/app/mscqr-alb-euw2/example"] }] });
  if (operation === "ec2 describe-subnets") return JSON.stringify({ Subnets: [{ VpcId: "vpc-1", State: "available", CidrBlock: "10.1.0.0/24" }, { VpcId: "vpc-1", State: "available", CidrBlock: "10.1.1.0/24" }] });
  if (operation === "ec2 describe-managed-prefix-lists") return JSON.stringify({ ManagedPrefixLists: [{ PrefixListId: "pl-0123456789abcdef0", State: "create-complete", Version: 7 }] });
  if (operation === "ec2 get-managed-prefix-list-entries") { assert.equal(args[args.indexOf("--target-version") + 1], "7"); return JSON.stringify({ Entries: [{ Cidr: "198.51.100.0/24" }] }); }
  if (operation === "cloudfront list-distributions") return JSON.stringify({ DistributionList: { Items: [{ Id: "E1", DomainName: "d1.cloudfront.net", Enabled: true, Status: "Deployed", Aliases: { Items: ["mscqr.com", "www.mscqr.com"] } }] } });
  if (operation === "cloudfront get-distribution-config") return JSON.stringify({ ETag: "E1", DistributionConfig: { Enabled: true, Aliases: { Items: ["mscqr.com", "www.mscqr.com"] }, Origins: { Items: [{ Id: "api", DomainName: "mscqr-alb.example.elb.amazonaws.com", CustomOriginConfig: { OriginProtocolPolicy: drift.originPolicy || "https-only", HTTPSPort: drift.originHttpsPort || 443 } }] }, OriginGroups: { Quantity: 0 }, DefaultCacheBehavior: { TargetOriginId: "api", ViewerProtocolPolicy: drift.viewerPolicy || "redirect-to-https" }, CacheBehaviors: { Quantity: 0 } } });
  if (operation === "route53 list-resource-record-sets") return JSON.stringify({ ResourceRecordSets: ["mscqr.com", "www.mscqr.com"].flatMap((Name) => ["A", "AAAA"].map((Type) => ({ Name, Type, AliasTarget: { DNSName: "d1.cloudfront.net.", HostedZoneId: "Z2FDTNDATAQYW2", EvaluateTargetHealth: false } }))) });
  throw new Error(`unexpected ${operation}`);
};

test("production proxy drift verifier accepts only an exact live task-definition binding", () => {
  assert.equal(verifyProductionCloudFrontProxyDrift({ run: run() }).status, "CURRENT");
  assert.throws(() => verifyProductionCloudFrontProxyDrift({ run: run({ version: true }) }), /prefix-list drift/);
  assert.throws(() => verifyProductionCloudFrontProxyDrift({ run: run({ cidr: true }) }), /prefix-list drift/);
  assert.throws(() => verifyProductionCloudFrontProxyDrift({ run: run({ xffMode: "preserve" }) }), /X-Forwarded-For attributes/);
  assert.throws(() => verifyProductionCloudFrontProxyDrift({ run: run({ clientPort: true }) }), /X-Forwarded-For attributes/);
  assert.throws(() => verifyProductionCloudFrontProxyDrift({ run: run({ attributesUnavailable: true }) }), /attributes are unavailable/);
  assert.throws(() => verifyProductionCloudFrontProxyDrift({ run: run({ viewerPolicy: "allow-all" }) }), /redirect viewers to HTTPS/);
  assert.throws(() => verifyProductionCloudFrontProxyDrift({ run: run({ originPolicy: "http-only" }) }), /HTTPS-only port 443/);
  assert.throws(() => verifyProductionCloudFrontProxyDrift({ run: run({ originPolicy: "match-viewer" }) }), /HTTPS-only port 443/);
  assert.throws(() => verifyProductionCloudFrontProxyDrift({ run: run({ originHttpsPort: 8443 }) }), /HTTPS-only port 443/);
});

test("scheduled proxy drift verification uses an exact unattended read-only OIDC boundary", () => {
  const workflow = fs.readFileSync(".github/workflows/verify-production-cloudfront-proxy-drift.yml", "utf8");
  const terraform = fs.readFileSync("infra/aws/terraform/production-green-stage-a/main.tf", "utf8");
  assert.match(workflow, /cron: "7,22,37,52 \* \* \* \*"/);
  assert.match(workflow, /id-token: write/);
  assert.doesNotMatch(workflow, /environment:\s*production/);
  assert.match(workflow, /role-to-assume: arn:aws:iam::368992683803:role\/mscqr-production-cloudfront-proxy-drift-readonly/);
  for (const binding of [
    '"token.actions.githubusercontent.com:sub"                 = "repo:T-ej2003/genuine-scan-main:ref:refs/heads/main"',
    '"token.actions.githubusercontent.com:repository_id"       = "1145608538"',
    '"token.actions.githubusercontent.com:repository_owner_id" = "183396573"',
    '"token.actions.githubusercontent.com:workflow"            = "Verify Production CloudFront Proxy Drift"',
    '"token.actions.githubusercontent.com:ref"                 = "refs/heads/main"',
  ]) assert.ok(terraform.includes(binding), `missing exact OIDC binding ${binding}`);
  const policy = terraform.match(/resource "aws_iam_role_policy" "cloudfront_proxy_drift_readonly" \{([\s\S]*?)\n\}/)?.[1] || "";
  for (const action of ["ecs:DescribeServices", "ecs:DescribeTaskDefinition", "elasticloadbalancing:DescribeLoadBalancers", "elasticloadbalancing:DescribeLoadBalancerAttributes", "elasticloadbalancing:DescribeTargetGroups", "ec2:DescribeSubnets", "ec2:DescribeManagedPrefixLists", "ec2:GetManagedPrefixListEntries", "cloudfront:ListDistributions", "cloudfront:GetDistributionConfig", "route53:ListResourceRecordSets"]) assert.ok(policy.includes(`"${action}"`), `missing ${action}`);
  assert.doesNotMatch(policy, /(?:Create|Delete|Put|Update|Register|RunTask|StopTask|Sign|ChangeResourceRecordSets)/);
  assert.match(fs.readFileSync(".github/workflows/release-gate.yml", "utf8"), /environment:\s*production/);
});
