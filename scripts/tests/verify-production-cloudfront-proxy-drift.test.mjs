import assert from "node:assert/strict";
import test from "node:test";
import { verifyProductionCloudFrontProxyDrift } from "../aws/verify-production-cloudfront-proxy-drift.mjs";

const run = (drift = {}) => (args) => {
  const operation = `${args[0]} ${args[1]}`;
  if (operation === "ecs describe-services") return JSON.stringify({ services: [{ taskDefinition: "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-backend-candidate:1" }] });
  if (operation === "ecs describe-task-definition") return JSON.stringify({ taskDefinition: { containerDefinitions: [{ name: "backend", environment: [
    { name: "CLIENT_IP_TRUST_MODE", value: "cloudfront-alb" }, { name: "CLIENT_IP_TRUSTED_ALB_CIDRS", value: "10.1.0.0/24,10.1.1.0/24" }, { name: "CLIENT_IP_TRUSTED_CLOUDFRONT_CIDRS", value: drift.cidr ? "198.51.101.0/24" : "198.51.100.0/24" }, { name: "MSCQR_CLIENT_IP_CLOUDFRONT_PREFIX_LIST_ID", value: "pl-0123456789abcdef0" }, { name: "MSCQR_CLIENT_IP_CLOUDFRONT_PREFIX_LIST_VERSION", value: drift.version ? "8" : "7" },
  ] }] } });
  if (operation === "elbv2 describe-load-balancers") return JSON.stringify({ LoadBalancers: [{ LoadBalancerArn: "arn:aws:elasticloadbalancing:eu-west-2:368992683803:loadbalancer/app/mscqr-alb-euw2/example", DNSName: "mscqr-alb.example.elb.amazonaws.com", Type: "application", Scheme: "internet-facing", VpcId: "vpc-1", AvailabilityZones: [{ SubnetId: "subnet-a" }, { SubnetId: "subnet-b" }] }] });
  if (operation === "elbv2 describe-target-groups") return JSON.stringify({ TargetGroups: [{ TargetGroupArn: "arn:aws:elasticloadbalancing:eu-west-2:368992683803:targetgroup/mscqr-backend-tg-euw2-v2/example", VpcId: "vpc-1", TargetType: "ip", Protocol: "HTTP", Port: 4000, HealthCheckPath: "/health/live", LoadBalancerArns: ["arn:aws:elasticloadbalancing:eu-west-2:368992683803:loadbalancer/app/mscqr-alb-euw2/example"] }] });
  if (operation === "ec2 describe-subnets") return JSON.stringify({ Subnets: [{ VpcId: "vpc-1", State: "available", CidrBlock: "10.1.0.0/24" }, { VpcId: "vpc-1", State: "available", CidrBlock: "10.1.1.0/24" }] });
  if (operation === "ec2 describe-managed-prefix-lists") return JSON.stringify({ ManagedPrefixLists: [{ PrefixListId: "pl-0123456789abcdef0", State: "create-complete", Version: 7 }] });
  if (operation === "ec2 get-managed-prefix-list-entries") return JSON.stringify({ Entries: [{ Cidr: "198.51.100.0/24" }] });
  if (operation === "cloudfront list-distributions") return JSON.stringify({ DistributionList: { Items: [{ Id: "E1", DomainName: "d1.cloudfront.net", Enabled: true, Status: "Deployed", Aliases: { Items: ["mscqr.com", "www.mscqr.com"] } }] } });
  if (operation === "cloudfront get-distribution-config") return JSON.stringify({ ETag: "E1", DistributionConfig: { Enabled: true, Aliases: { Items: ["mscqr.com", "www.mscqr.com"] }, Origins: { Items: [{ Id: "api", DomainName: "mscqr-alb.example.elb.amazonaws.com" }] }, OriginGroups: { Quantity: 0 }, DefaultCacheBehavior: { TargetOriginId: "api" }, CacheBehaviors: { Quantity: 0 } } });
  if (operation === "route53 list-resource-record-sets") return JSON.stringify({ ResourceRecordSets: ["mscqr.com", "www.mscqr.com"].flatMap((Name) => ["A", "AAAA"].map((Type) => ({ Name, Type, AliasTarget: { DNSName: "d1.cloudfront.net.", HostedZoneId: "Z2FDTNDATAQYW2", EvaluateTargetHealth: false } }))) });
  throw new Error(`unexpected ${operation}`);
};

test("production proxy drift verifier accepts only an exact live task-definition binding", () => {
  assert.equal(verifyProductionCloudFrontProxyDrift({ run: run() }).status, "CURRENT");
  assert.throws(() => verifyProductionCloudFrontProxyDrift({ run: run({ version: true }) }), /prefix-list drift/);
  assert.throws(() => verifyProductionCloudFrontProxyDrift({ run: run({ cidr: true }) }), /prefix-list drift/);
});
