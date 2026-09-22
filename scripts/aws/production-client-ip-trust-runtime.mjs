#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";
import { isIP } from "node:net";
import { pathToFileURL } from "node:url";

export const PRODUCTION_CLIENT_IP_TRUST = Object.freeze({
  account: "368992683803",
  region: "eu-west-2",
  cluster: "mscqr-prod-euw2-main",
  clusterArn: "arn:aws:ecs:eu-west-2:368992683803:cluster/mscqr-prod-euw2-main",
  service: "mscqr-backend-servi-euw2",
  serviceArn: "arn:aws:ecs:eu-west-2:368992683803:service/mscqr-prod-euw2-main/mscqr-backend-servi-euw2",
  container: "backend",
  targetGroupArn: "arn:aws:elasticloadbalancing:eu-west-2:368992683803:targetgroup/mscqr-backend-tg-euw2-v2/f6673ff776f6e2ec",
  loadBalancerArn: "arn:aws:elasticloadbalancing:eu-west-2:368992683803:loadbalancer/app/mscqr-alb-euw2/cda0292be6e39608",
  albSubnetCidrs: Object.freeze(["10.0.0.0/20", "10.0.16.0/20"]),
  cloudFrontPrefixListName: "com.amazonaws.global.cloudfront.origin-facing",
});

export const CLIENT_IP_ENVIRONMENT_NAMES = Object.freeze([
  "CLIENT_IP_TRUST_MODE",
  "CLIENT_IP_TRUSTED_ALB_CIDRS",
  "CLIENT_IP_TRUSTED_CLOUDFRONT_CIDRS",
]);

const plainObject = (value) => value !== null && typeof value === "object" && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
const canonicalCidrs = (values, label) => {
  assert(Array.isArray(values) && values.length > 0, `${label} must be non-empty.`);
  const cidrs = [...new Set(values.map((value) => String(value || "").trim()))].sort();
  for (const cidr of cidrs) {
    const match = /^(\d{1,3}(?:\.\d{1,3}){3})\/(\d|[12]\d|3[0-2])$/.exec(cidr);
    assert(match && isIP(match[1]) === 4, `${label} contains an invalid IPv4 CIDR.`);
    const prefix = Number(match[2]);
    assert(prefix > 0 && cidr !== "0.0.0.0/0", `${label} contains a universal CIDR.`);
    const value = match[1].split(".").reduce((number, octet) => (number * 256 + Number(octet)) >>> 0, 0);
    const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
    assert((value & mask) >>> 0 === value, `${label} contains a non-canonical network address.`);
  }
  return cidrs;
};

export function deriveProductionClientIpTrustRuntime({ service, targetGroups, loadBalancers, subnets, prefixLists, prefixListEntries } = {}) {
  const contract = PRODUCTION_CLIENT_IP_TRUST;
  assert.deepEqual(service?.failures, [], "ECS service discovery returned failures.");
  assert.equal(service?.services?.length, 1, "Exact production backend service was not discovered once.");
  assert.equal(service.services[0].serviceName, contract.service);
  assert.equal(service.services[0].serviceArn, contract.serviceArn);
  assert.equal(service.services[0].clusterArn, contract.clusterArn);
  const binding = service.services[0].loadBalancers;
  assert.deepEqual(binding, [{ targetGroupArn: contract.targetGroupArn, containerName: contract.container, containerPort: 4000 }], "Production backend target-group binding changed.");

  assert.equal(targetGroups?.TargetGroups?.length, 1, "Exact production backend target group was not discovered once.");
  const targetGroup = targetGroups.TargetGroups[0];
  assert.equal(targetGroup.TargetGroupArn, contract.targetGroupArn);
  assert.deepEqual(targetGroup.LoadBalancerArns, [contract.loadBalancerArn]);
  assert.match(targetGroup.VpcId || "", /^vpc-[A-Za-z0-9-]+$/);
  assert.equal(targetGroup.TargetType, "ip");
  assert.equal(targetGroup.Protocol, "HTTP");
  assert.equal(targetGroup.Port, 4000);

  assert.equal(loadBalancers?.LoadBalancers?.length, 1, "Exact production ALB was not discovered once.");
  const loadBalancer = loadBalancers.LoadBalancers[0];
  assert.equal(loadBalancer.LoadBalancerArn, contract.loadBalancerArn);
  assert.equal(loadBalancer.Type, "application");
  assert.equal(loadBalancer.Scheme, "internet-facing");
  assert.equal(loadBalancer.VpcId, targetGroup.VpcId);
  assert.equal(loadBalancer.State?.Code, "active");
  const subnetIds = (loadBalancer.AvailabilityZones || []).map(({ SubnetId }) => SubnetId).sort();
  assert.equal(subnetIds.length, 2, "Production ALB must use exactly two subnets.");
  assert.equal(new Set(subnetIds).size, subnetIds.length, "Production ALB subnet identity is duplicated.");
  for (const subnetId of subnetIds) assert.match(subnetId || "", /^subnet-[A-Za-z0-9-]+$/);

  assert.equal(subnets?.Subnets?.length, subnetIds.length, "Production ALB subnet discovery is incomplete.");
  const discoveredSubnets = Object.fromEntries(subnets.Subnets.map((subnet) => {
    assert.equal(subnet.VpcId, targetGroup.VpcId);
    assert.equal(subnet.State, "available");
    return [subnet.SubnetId, subnet.CidrBlock];
  }));
  assert.deepEqual(Object.keys(discoveredSubnets).sort(), subnetIds, "Production ALB subnet discovery returned another subnet.");
  const albCidrs = canonicalCidrs(Object.values(discoveredSubnets), "ALB CIDRs");
  assert.deepEqual(albCidrs, [...contract.albSubnetCidrs], "Production ALB subnet CIDRs changed.");

  assert.equal(prefixLists?.PrefixLists?.length, 1, "CloudFront origin-facing managed prefix list was not discovered once.");
  const prefixList = prefixLists.PrefixLists[0];
  assert.equal(prefixList.PrefixListName, contract.cloudFrontPrefixListName);
  assert.equal(prefixList.OwnerId, "AWS");
  assert.equal(prefixList.AddressFamily, "IPv4");
  assert.equal(prefixList.State, "create-complete");
  assert.match(prefixList.PrefixListId || "", /^pl-[a-f0-9]+$/);
  assert.equal(prefixList.PrefixListArn, `arn:aws:ec2:${contract.region}:aws:prefix-list/${prefixList.PrefixListId}`);
  assert.equal(prefixListEntries?.NextToken, undefined, "CloudFront managed prefix-list entries are incomplete.");
  const cloudFrontCidrs = canonicalCidrs((prefixListEntries?.Entries || []).map(({ Cidr }) => Cidr), "CloudFront CIDRs");

  return Object.freeze({
    prefixListId: prefixList.PrefixListId,
    prefixListName: prefixList.PrefixListName,
    cidrCount: cloudFrontCidrs.length,
    environment: Object.freeze({
      CLIENT_IP_TRUST_MODE: "cloudfront-alb",
      CLIENT_IP_TRUSTED_ALB_CIDRS: albCidrs.join(","),
      CLIENT_IP_TRUSTED_CLOUDFRONT_CIDRS: cloudFrontCidrs.join(","),
    }),
  });
}

export function applyProductionClientIpTrustRuntime(definition, runtime) {
  assert(plainObject(definition) && plainObject(runtime?.environment), "Authenticated client-IP runtime is required.");
  assert.deepEqual(Object.keys(runtime.environment).sort(), [...CLIENT_IP_ENVIRONMENT_NAMES].sort());
  const candidate = structuredClone(definition);
  const containers = candidate.containerDefinitions?.filter(({ name }) => name === PRODUCTION_CLIENT_IP_TRUST.container) || [];
  assert.equal(containers.length, 1, "Candidate must contain the exact production backend container.");
  const container = containers[0];
  const existing = Array.isArray(container.environment) ? container.environment : [];
  container.environment = [
    ...existing.filter(({ name }) => !CLIENT_IP_ENVIRONMENT_NAMES.includes(name)),
    ...CLIENT_IP_ENVIRONMENT_NAMES.map((name) => ({ name, value: runtime.environment[name] })),
  ];
  return candidate;
}

export function assertProductionClientIpTrustRuntime(definition, runtime) {
  assert(plainObject(runtime?.environment), "Authenticated client-IP runtime is required.");
  const containers = definition?.containerDefinitions?.filter(({ name }) => name === PRODUCTION_CLIENT_IP_TRUST.container) || [];
  assert.equal(containers.length, 1, "Candidate must contain the exact production backend container.");
  const environment = containers[0].environment;
  assert(Array.isArray(environment), "Candidate backend environment is missing.");
  for (const name of CLIENT_IP_ENVIRONMENT_NAMES) {
    const entries = environment.filter((entry) => entry?.name === name);
    assert.equal(entries.length, 1, `Candidate backend ${name} must appear exactly once.`);
    assert.equal(entries[0].value, runtime.environment[name], `Candidate backend ${name} is not authenticated.`);
  }
  assert.equal(runtime.environment.CLIENT_IP_TRUST_MODE, "cloudfront-alb");
  canonicalCidrs(runtime.environment.CLIENT_IP_TRUSTED_ALB_CIDRS.split(","), "ALB CIDRs");
  canonicalCidrs(runtime.environment.CLIENT_IP_TRUSTED_CLOUDFRONT_CIDRS.split(","), "CloudFront CIDRs");
  return true;
}

const argsMap = (argv) => {
  const values = new Map();
  for (let index = 0; index < argv.length; index += 2) {
    assert(argv[index]?.startsWith("--") && argv[index + 1] && !values.has(argv[index]), `Invalid argument: ${argv[index] || "<missing>"}`);
    values.set(argv[index], argv[index + 1]);
  }
  assert.deepEqual([...values.keys()].sort(), ["--load-balancers", "--output", "--prefix-list-entries", "--prefix-lists", "--service", "--subnets", "--target-groups"]);
  return values;
};

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  const values = argsMap(process.argv.slice(2));
  const read = (name) => JSON.parse(fs.readFileSync(values.get(name), "utf8"));
  const runtime = deriveProductionClientIpTrustRuntime({
    service: read("--service"),
    targetGroups: read("--target-groups"),
    loadBalancers: read("--load-balancers"),
    subnets: read("--subnets"),
    prefixLists: read("--prefix-lists"),
    prefixListEntries: read("--prefix-list-entries"),
  });
  fs.writeFileSync(values.get("--output"), `${JSON.stringify(runtime)}\n`, { mode: 0o600 });
}
