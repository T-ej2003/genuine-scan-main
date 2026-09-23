import assert from "node:assert/strict";
import test from "node:test";
import {
  applyProductionClientIpTrustRuntime,
  assertProductionClientIpTrustRuntime,
  AWS_MANAGED_PREFIX_LIST_STATES,
  deriveProductionClientIpTrustRuntime,
  PRODUCTION_CLIENT_IP_TRUST,
  USABLE_MANAGED_PREFIX_LIST_STATES,
} from "../aws/production-client-ip-trust-runtime.mjs";

const topology = () => ({
  service: { failures: [], services: [{ serviceName: PRODUCTION_CLIENT_IP_TRUST.service, serviceArn: PRODUCTION_CLIENT_IP_TRUST.serviceArn, clusterArn: PRODUCTION_CLIENT_IP_TRUST.clusterArn, loadBalancers: [{ targetGroupArn: PRODUCTION_CLIENT_IP_TRUST.targetGroupArn, containerName: "backend", containerPort: 4000 }] }] },
  targetGroups: { TargetGroups: [{ TargetGroupArn: PRODUCTION_CLIENT_IP_TRUST.targetGroupArn, LoadBalancerArns: [PRODUCTION_CLIENT_IP_TRUST.loadBalancerArn], VpcId: "vpc-example", TargetType: "ip", Protocol: "HTTP", Port: 4000 }] },
  loadBalancers: { LoadBalancers: [{ LoadBalancerArn: PRODUCTION_CLIENT_IP_TRUST.loadBalancerArn, Type: "application", Scheme: "internet-facing", VpcId: "vpc-example", State: { Code: "active" }, AvailabilityZones: [{ SubnetId: "subnet-a" }, { SubnetId: "subnet-b" }] }] },
  subnets: { Subnets: [{ SubnetId: "subnet-a", CidrBlock: "10.0.0.0/20", VpcId: "vpc-example", State: "available" }, { SubnetId: "subnet-b", CidrBlock: "10.0.16.0/20", VpcId: "vpc-example", State: "available" }] },
  prefixLists: { PrefixLists: [{ PrefixListName: PRODUCTION_CLIENT_IP_TRUST.cloudFrontPrefixListName, PrefixListId: "pl-93a247fa", PrefixListArn: "arn:aws:ec2:eu-west-2:aws:prefix-list/pl-93a247fa", OwnerId: "AWS", AddressFamily: "IPv4", State: "create-complete" }] },
  prefixListEntries: { Entries: [{ Cidr: "198.51.100.0/24" }, { Cidr: "192.0.2.0/24" }, { Cidr: "198.51.100.0/24" }] },
});

const definition = () => ({ containerDefinitions: [{ name: "backend", environment: [{ name: "OTHER", value: "kept" }] }] });

test("authenticated topology deterministically produces and injects the production client-IP runtime", () => {
  const runtime = deriveProductionClientIpTrustRuntime(topology());
  assert.deepEqual(runtime.environment, {
    CLIENT_IP_TRUST_MODE: "cloudfront-alb",
    CLIENT_IP_TRUSTED_ALB_CIDRS: "10.0.0.0/20,10.0.16.0/20",
    CLIENT_IP_TRUSTED_CLOUDFRONT_CIDRS: "192.0.2.0/24,198.51.100.0/24",
  });
  assert.equal(runtime.prefixListId, "pl-93a247fa");
  assert.equal(runtime.cidrCount, 2);
  assertProductionClientIpTrustRuntime(applyProductionClientIpTrustRuntime(definition(), runtime), runtime);
});

test("every documented managed-prefix-list state has an explicit fail-closed disposition", () => {
  assert.deepEqual(AWS_MANAGED_PREFIX_LIST_STATES, [
    "create-in-progress", "create-complete", "create-failed",
    "modify-in-progress", "modify-complete", "modify-failed",
    "restore-in-progress", "restore-complete", "restore-failed",
    "delete-in-progress", "delete-complete", "delete-failed",
  ]);
  assert.deepEqual(USABLE_MANAGED_PREFIX_LIST_STATES, ["create-complete", "modify-complete", "restore-complete"]);
  for (const state of [...AWS_MANAGED_PREFIX_LIST_STATES, "future-complete"]) {
    const value = topology();
    value.prefixLists.PrefixLists[0].State = state;
    if (USABLE_MANAGED_PREFIX_LIST_STATES.includes(state)) assert.doesNotThrow(() => deriveProductionClientIpTrustRuntime(value), state);
    else assert.throws(() => deriveProductionClientIpTrustRuntime(value), /usable completed state/, state);
  }
});

test("topology authority and unsafe CIDRs fail closed", () => {
  for (const mutate of [
    (value) => { value.service.services[0].loadBalancers[0].targetGroupArn = "arn:aws:elasticloadbalancing:eu-west-2:368992683803:targetgroup/other/123"; },
    (value) => { value.targetGroups.TargetGroups[0].LoadBalancerArns = ["arn:aws:elasticloadbalancing:eu-west-2:368992683803:loadbalancer/app/other/123"]; },
    (value) => { value.subnets.Subnets[0].CidrBlock = "10.0.32.0/20"; },
    (value) => { value.prefixLists.PrefixLists[0].OwnerId = "368992683803"; },
    (value) => { value.prefixLists.PrefixLists[0].PrefixListName = "other"; },
    (value) => { value.prefixListEntries.Entries = []; },
    (value) => { value.prefixListEntries.Entries = [{ Cidr: "0.0.0.0/0" }]; },
    (value) => { value.prefixListEntries.NextToken = "incomplete"; },
  ]) {
    const value = topology(); mutate(value);
    assert.throws(() => deriveProductionClientIpTrustRuntime(value));
  }
});

test("candidate preflight rejects missing, wrong, empty, universal, duplicate, and unauthenticated values", () => {
  const runtime = deriveProductionClientIpTrustRuntime(topology());
  const approved = applyProductionClientIpTrustRuntime(definition(), runtime);
  for (const mutate of [
    (value) => { value.containerDefinitions[0].environment = value.containerDefinitions[0].environment.filter(({ name }) => name !== "CLIENT_IP_TRUST_MODE"); },
    (value) => { value.containerDefinitions[0].environment.find(({ name }) => name === "CLIENT_IP_TRUST_MODE").value = "direct"; },
    (value) => { value.containerDefinitions[0].environment = value.containerDefinitions[0].environment.filter(({ name }) => name !== "CLIENT_IP_TRUSTED_ALB_CIDRS"); },
    (value) => { value.containerDefinitions[0].environment.find(({ name }) => name === "CLIENT_IP_TRUSTED_ALB_CIDRS").value = ""; },
    (value) => { value.containerDefinitions[0].environment = value.containerDefinitions[0].environment.filter(({ name }) => name !== "CLIENT_IP_TRUSTED_CLOUDFRONT_CIDRS"); },
    (value) => { value.containerDefinitions[0].environment.find(({ name }) => name === "CLIENT_IP_TRUSTED_CLOUDFRONT_CIDRS").value = ""; },
    (value) => { value.containerDefinitions[0].environment.find(({ name }) => name === "CLIENT_IP_TRUSTED_ALB_CIDRS").value = "0.0.0.0/0"; },
    (value) => { value.containerDefinitions[0].environment.find(({ name }) => name === "CLIENT_IP_TRUSTED_CLOUDFRONT_CIDRS").value = "0.0.0.0/0"; },
    (value) => { value.containerDefinitions[0].environment.push({ name: "CLIENT_IP_TRUST_MODE", value: "cloudfront-alb" }); },
  ]) {
    const value = structuredClone(approved); mutate(value);
    assert.throws(() => assertProductionClientIpTrustRuntime(value, runtime));
  }
  assert.throws(() => assertProductionClientIpTrustRuntime(approved, {}));
});
