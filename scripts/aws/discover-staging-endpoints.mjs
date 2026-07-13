#!/usr/bin/env node
import process from "node:process";
import { spawnSync } from "node:child_process";
import { lookup } from "node:dns/promises";

const C = Object.freeze({
  accountId: "368992683803",
  region: "eu-west-2",
  profile: "mscqr-staging-plan",
  planRole: "mscqr-staging-terraform-plan-role",
  cluster: "mscqr-staging-euw2-main",
  service: "mscqr-staging-backend-service-euw2",
});

function fail(message) { throw new Error(message); }
function awsJson(args) {
  const result = spawnSync("aws", [...args, "--profile", C.profile, "--region", C.region, "--output", "json"], { encoding: "utf8", maxBuffer: 32 * 1024 * 1024, stdio: ["ignore", "pipe", "pipe"] });
  if (result.error || result.status !== 0) fail(`Read-only AWS endpoint discovery failed for ${args[0]}:${args[1]}; output was suppressed.`);
  try { return JSON.parse(result.stdout || "{}"); }
  catch { fail("AWS endpoint discovery returned invalid JSON."); }
}
const stagingName = (value) => /(?:staging|stg)/i.test(String(value || "")) && !/(?:prod|production)/i.test(String(value || ""));
const stripDot = (value) => String(value || "").replace(/\.$/, "");
const actionTargetGroups = (listener) => (listener.DefaultActions || []).filter((action) => action.Type === "forward").flatMap((action) => action.TargetGroupArn ? [action.TargetGroupArn] : (action.ForwardConfig?.TargetGroups || []).map((target) => target.TargetGroupArn));

export async function discoverStagingEndpoints() {
  if (process.env.AWS_PROFILE !== C.profile) fail(`AWS_PROFILE must be the approved read-only staging profile ${C.profile}.`);
  if ((process.env.AWS_REGION || process.env.AWS_DEFAULT_REGION || C.region) !== C.region) fail(`AWS region must be ${C.region}.`);

  const identity = awsJson(["sts", "get-caller-identity"]);
  const expectedPrefix = `arn:aws:sts::${C.accountId}:assumed-role/${C.planRole}/`;
  if (identity.Account !== C.accountId || !String(identity.Arn || "").startsWith(expectedPrefix)) fail("Endpoint discovery requires the exact staging Terraform plan role.");

  const serviceResponse = awsJson(["ecs", "describe-services", "--cluster", C.cluster, "--services", C.service]);
  const service = serviceResponse.services?.[0];
  if (!service || serviceResponse.failures?.length) fail("Exact staging ECS service was not found.");
  const attachments = service.loadBalancers || [];
  const targetGroups = attachments.map((attachment) => awsJson(["elbv2", "describe-target-groups", "--target-group-arns", attachment.targetGroupArn]).TargetGroups?.[0]).filter(Boolean);
  const loadBalancerArns = [...new Set(targetGroups.flatMap((targetGroup) => targetGroup.LoadBalancerArns || []))];
  const loadBalancers = loadBalancerArns.map((arn) => awsJson(["elbv2", "describe-load-balancers", "--load-balancer-arns", arn]).LoadBalancers?.[0]).filter(Boolean);
  const listeners = loadBalancerArns.flatMap((arn) => awsJson(["elbv2", "describe-listeners", "--load-balancer-arn", arn]).Listeners || []);

  const restApis = (awsJson(["apigateway", "get-rest-apis", "--limit", "500"]).items || []).map((api) => ({ id: api.id, name: api.name, endpointTypes: api.endpointConfiguration?.types || [], stagingCandidate: stagingName(api.name) }));
  const httpApis = (awsJson(["apigatewayv2", "get-apis", "--max-results", "100"]).Items || []).map((api) => ({ apiId: api.ApiId, name: api.Name, protocolType: api.ProtocolType, apiEndpoint: api.ApiEndpoint, stagingCandidate: stagingName(api.Name) }));
  const cloudfront = (awsJson(["cloudfront", "list-distributions"]).DistributionList?.Items || []).map((distribution) => ({ id: distribution.Id, domainName: distribution.DomainName, aliases: distribution.Aliases?.Items || [], origins: (distribution.Origins?.Items || []).map((origin) => origin.DomainName), enabled: distribution.Enabled, stagingCandidate: stagingName(distribution.Comment) || (distribution.Aliases?.Items || []).some(stagingName) }));
  const hostedZones = awsJson(["route53", "list-hosted-zones"]).HostedZones || [];
  const route53Records = hostedZones.flatMap((zone) => (awsJson(["route53", "list-resource-record-sets", "--hosted-zone-id", zone.Id]).ResourceRecordSets || [])
    .filter((record) => ["A", "AAAA", "CNAME"].includes(record.Type) && stagingName(record.Name))
    .map((record) => ({ zoneId: zone.Id, zoneName: stripDot(zone.Name), name: stripDot(record.Name), type: record.Type, aliasTarget: stripDot(record.AliasTarget?.DNSName), values: (record.ResourceRecords || []).map((item) => stripDot(item.Value)) })));

  const attachedTargetGroupArns = new Set(attachments.map((attachment) => attachment.targetGroupArn));
  const reviewedAlbOrigins = loadBalancers.flatMap((loadBalancer) => {
    const relevantListeners = listeners.filter((listener) => listener.LoadBalancerArn === loadBalancer.LoadBalancerArn && actionTargetGroups(listener).some((arn) => attachedTargetGroupArns.has(arn)));
    if (loadBalancer.State?.Code !== "active" || !stagingName(loadBalancer.LoadBalancerName) || !stagingName(loadBalancer.DNSName) || relevantListeners.length === 0) return [];
    const protocol = relevantListeners.some((listener) => listener.Protocol === "HTTPS" && listener.Port === 443) ? "https" : relevantListeners.some((listener) => listener.Protocol === "HTTP" && listener.Port === 80) ? "http" : "";
    return protocol ? [`${protocol}://${loadBalancer.DNSName}`] : [];
  });
  const reviewedDnsOrigins = route53Records.flatMap((record) => {
    const targets = [record.aliasTarget, ...record.values].filter(Boolean);
    const alb = loadBalancers.find((item) => targets.includes(stripDot(item.DNSName)));
    if (!alb) return [];
    const albListeners = listeners.filter((listener) => listener.LoadBalancerArn === alb.LoadBalancerArn);
    const protocol = albListeners.some((listener) => listener.Protocol === "HTTPS" && listener.Port === 443) ? "https" : albListeners.some((listener) => listener.Protocol === "HTTP" && listener.Port === 80) ? "http" : "";
    return protocol ? [`${protocol}://${record.name}`] : [];
  });
  const reviewedOrigins = [...new Set([...reviewedDnsOrigins, ...reviewedAlbOrigins])];
  if (reviewedOrigins.length !== 1) fail(`Expected exactly one reviewed staging origin; found ${reviewedOrigins.length}.`);
  const reviewedUrl = new URL(reviewedOrigins[0]);
  if (process.env.NODE_ENV === "test" && process.env.MSCQR_TEST_STAGING_ENDPOINT_DNS_RESOLVED === "true") {
    // Test-only deterministic resolver bypass. Production invocation always uses DNS.
  } else {
    try { await lookup(reviewedUrl.hostname); } catch { fail("Reviewed staging hostname did not resolve."); }
  }

  return {
    status: "reviewed_staging_endpoint_discovered",
    mutatesAws: false,
    accountId: identity.Account,
    region: C.region,
    profile: C.profile,
    identityRole: C.planRole,
    ecsService: {
      cluster: C.cluster,
      service: C.service,
      taskDefinition: service.taskDefinition,
      loadBalancerAttachments: attachments,
    },
    targetGroups: targetGroups.map((targetGroup) => ({ targetGroupArn: targetGroup.TargetGroupArn, targetGroupName: targetGroup.TargetGroupName, protocol: targetGroup.Protocol, port: targetGroup.Port, healthCheckPath: targetGroup.HealthCheckPath, loadBalancerArns: targetGroup.LoadBalancerArns || [] })),
    loadBalancers: loadBalancers.map((loadBalancer) => ({ loadBalancerArn: loadBalancer.LoadBalancerArn, loadBalancerName: loadBalancer.LoadBalancerName, dnsName: loadBalancer.DNSName, scheme: loadBalancer.Scheme, type: loadBalancer.Type, state: loadBalancer.State?.Code })),
    listeners: listeners.map((listener) => ({ listenerArn: listener.ListenerArn, loadBalancerArn: listener.LoadBalancerArn, protocol: listener.Protocol, port: listener.Port, targetGroupArns: actionTargetGroups(listener) })),
    apiGatewayRestCandidates: restApis,
    apiGatewayV2Candidates: httpApis,
    cloudFrontCandidates: cloudfront,
    route53StagingRecords: route53Records,
    reviewedStagingBaseUrl: reviewedOrigins[0],
    reviewedStagingHealthUrl: `${reviewedOrigins[0]}/health/live`,
  };
}

if (process.argv[1] && import.meta.filename === process.argv[1]) {
  try { console.log(JSON.stringify(await discoverStagingEndpoints(), null, 2)); }
  catch (error) { console.error(JSON.stringify({ status: "blocked", reason: error.message, mutatesAws: false }, null, 2)); process.exitCode = 2; }
}
