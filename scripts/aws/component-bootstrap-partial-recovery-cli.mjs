#!/usr/bin/env node
// Exact one-time repair for the authenticated September 2026 partial bootstrap.
// It is not an identity bootstrap, broker updater, or general Lambda interface.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import { execFileSync } from "node:child_process";
import { pathToFileURL } from "node:url";
import { cleanSource } from "./component-iam-installation.mjs";
import { buildComponentBrokerPackage } from "./component-broker-package.mjs";
import { authenticateBootstrapRecoveryPublication } from "./component-iam-authorization.mjs";
import { executeBootstrapRecovery } from "./component-bootstrap-partial-recovery.mjs";
import { bootstrapRecoveryCapabilitySet, historicalBootstrapIncident } from "./component-bootstrap-partial-recovery-contract.mjs";
import { authenticateBootstrapOperator } from "./component-bootstrap-operator.mjs";
import { brokerConfiguration } from "./component-broker-configuration.mjs";
import { bootstrapManagedIdentities, identityBootstrap } from "./component-installation-identity-contract.mjs";
import { installationIdentity } from "./component-iam-installation-contract.mjs";
import { createProductionAwsCredentialEnvironment, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "./production-credential-source-contract.mjs";

const sdk = createRequire(new URL("../../infra/aws/terraform/production-component-deployment-state/broker-package/package.json", import.meta.url));
const administrator = "arn:aws:iam::368992683803:root";

async function recoveryAdministrativeAdapter(packageEvidence) {
  assert.equal(packageEvidence.packageSha256, createHash("sha256").update(packageEvidence.bytes).digest("hex"));
  const configurations = Object.fromEntries(["INSTALL", "CLEANUP", "AUTHORIZE"].map(entryPoint => [entryPoint,
    brokerConfiguration({ packageSha256: packageEvidence.packageSha256, manifestSha256: packageEvidence.manifestSha256, entryPoint })]));
  let exported; const clients = [];
  try {
    exported = JSON.parse(execFileSync("aws", ["configure", "export-credentials", "--format", "process"], {
      env: createProductionAwsCredentialEnvironment({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE, profile: "default", region: "eu-west-2" }),
      encoding: "utf8", stdio: ["ignore", "pipe", "pipe"],
    }));
    const credentials = { accessKeyId: exported.AccessKeyId, secretAccessKey: exported.SecretAccessKey, ...(exported.SessionToken ? { sessionToken: exported.SessionToken } : {}) };
    for (const value of Object.values(credentials)) assert(typeof value === "string" && value);
    const create = (service, className, endpoint, region = "eu-west-2") => {
      const library = sdk(`@aws-sdk/client-${service}`), client = new library[`${className}Client`]({ credentials, region, endpoint, maxAttempts: 1 }); clients.push(client);
      return async (operation, input = {}) => client.send(new library[`${operation}Command`](input));
    };
    const sts = create("sts", "STS", "https://sts.eu-west-2.amazonaws.com");
    const authenticate = async () => { const caller = await sts("GetCallerIdentity"); assert.equal(caller.Account, "368992683803"); assert.equal(caller.Arn, administrator); };
    await authenticate();
    const permitted = new Set(bootstrapRecoveryCapabilitySet().Statement.flatMap(statement => [].concat(statement.Action)));
    const confined = (service, name, endpoint, region) => {
      const send = create(service, name, endpoint, region);
      return (operation, input = {}) => {
        assert(permitted.has(`${service}:${service === "s3" && operation === "ListObjectsV2" ? "ListBucket" : operation}`), "Unsupported recovery API");
        if (service === "lambda") {
          assert.equal(input.FunctionName, installationIdentity.functionName, "Alternate recovery function forbidden");
          if (input.Qualifier !== undefined) assert(["1", "2", "3"].includes(input.Qualifier), "Alternate recovery qualifier forbidden");
          if (operation === "UpdateFunctionCode") {
            assert.deepEqual(Object.keys(input).sort(), ["FunctionName", "Publish", "RevisionId", "ZipFile"]); assert.equal(input.Publish, false);
            assert(Buffer.isBuffer(input.ZipFile)); assert.equal(createHash("sha256").update(input.ZipFile).digest("hex"), packageEvidence.packageSha256);
            assert.equal(input.RevisionId, historicalBootstrapIncident.revisionId);
          } else if (operation === "UpdateFunctionConfiguration") {
            assert.deepEqual(Object.keys(input).sort(), ["Description", "FunctionName", "RevisionId"]); assert(Object.values(configurations).some(({ Description }) => Description === input.Description));
            assert.equal(typeof input.RevisionId, "string");
          } else if (operation === "PublishVersion") {
            assert.deepEqual(Object.keys(input).sort(), ["CodeSha256", "Description", "FunctionName", "RevisionId"]);
            assert.equal(input.CodeSha256, Buffer.from(packageEvidence.packageSha256, "hex").toString("base64"));
            assert(Object.values(configurations).some(({ Description }) => Description === input.Description)); assert.equal(typeof input.RevisionId, "string");
          } else if (operation === "PutFunctionConcurrency") {
            assert.deepEqual(input, { FunctionName: installationIdentity.functionName, ReservedConcurrentExecutions: 1 });
          } else if (operation === "PutRuntimeManagementConfig") {
            assert.deepEqual(input, { FunctionName: installationIdentity.functionName, UpdateRuntimeOn: "FunctionUpdate" });
          }
        } else if (service === "iam") assert(bootstrapManagedIdentities().some(({ role }) => role === input.RoleName), "Alternate recovery role forbidden");
        else {
          assert.equal(input.Bucket, identityBootstrap.bucket); assert.equal(input.Key || input.Prefix, `${identityBootstrap.prefix}identity-bootstrap.json`);
        }
        return send(operation, input);
      };
    };
    const cloudtrail = create("cloudtrail", "CloudTrail", "https://cloudtrail.eu-west-2.amazonaws.com");
    return {
      iam: confined("iam", "IAM", "https://iam.amazonaws.com", "us-east-1"),
      lambda: confined("lambda", "Lambda", "https://lambda.eu-west-2.amazonaws.com"),
      s3: confined("s3", "S3", "https://s3.eu-west-2.amazonaws.com"), authenticate,
      async issuanceEvents() {
        const values = new Map(), tokens = new Set(); let NextToken; const end = new Date(), start = new Date(end.getTime() - 3600000);
        do {
          const response = await cloudtrail("LookupEvents", { LookupAttributes: [{ AttributeKey: "EventName", AttributeValue: "AssumeRole" }], StartTime: start, EndTime: end, ...(NextToken ? { NextToken } : {}) });
          assert(Array.isArray(response.Events));
          for (const value of response.Events) { const event = JSON.parse(value.CloudTrailEvent); assert.equal(event.eventID, value.EventId); if (values.has(event.eventID)) assert.deepEqual(values.get(event.eventID), event); values.set(event.eventID, event); }
          NextToken = response.NextToken; if (NextToken) { assert(typeof NextToken === "string" && !tokens.has(NextToken) && tokens.size < 20); tokens.add(NextToken); }
        } while (NextToken);
        return [...values.values()];
      },
      close() { for (const client of clients) client.destroy(); for (const key of Object.keys(credentials)) delete credentials[key]; },
    };
  } catch (error) { for (const client of clients) client.destroy(); throw error; }
  finally { if (exported) for (const field of ["AccessKeyId", "SecretAccessKey", "SessionToken"]) delete exported[field]; }
}

export async function run(argv = process.argv.slice(2), { source = cleanSource, build = buildComponentBrokerPackage,
  authorize = authenticateBootstrapRecoveryPublication, admin = recoveryAdministrativeAdapter, human = authenticateBootstrapOperator, execute = executeBootstrapRecovery } = {}) {
  const [mode, runId, transitionId] = argv; assert.equal(mode, "execute"); assert.equal(argv.length, 3);
  assert.match(runId || "", /^[1-9][0-9]*$/); assert.match(transitionId || "", /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/);
  const sourceSha = source(), packageEvidence = await build(); assert.equal(packageEvidence.manifest.sourceSha, sourceSha);
  const approved = authorize({ runId, transitionId, sourceSha }, packageEvidence); const { authorizationSha256, ...authorization } = approved;
  assert.equal(source(), sourceSha);
  const authority = await admin(packageEvidence);
  try {
    const operatorProof = await human({ sourceSha, transitionId, authorizationSha256, purpose: "IDENTITY_BOOTSTRAP" }, { issuanceEvents: authority.issuanceEvents });
    const result = await execute({ authorization, packageEvidence, operatorProof }, { ...authority, authenticate: async () => { assert.equal(source(), sourceSha, "Protected main moved during recovery"); await authority.authenticate(); } });
    assert.equal(result.state, "BOOTSTRAP_CLOSED"); return { state: result.state, sourceSha, transitionId, authorizationSha256 };
  } finally { authority.close(); }
}

if (import.meta.url === pathToFileURL(process.argv[1] || "").href) run().then(result => process.stdout.write(`${JSON.stringify(result)}\n`)).catch(() => {
  process.stderr.write("Component bootstrap recovery rejected; preserve the durable journal and reconcile exact live targets.\n"); process.exitCode = 1;
});
