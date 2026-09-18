#!/usr/bin/env node
// Exceptional INITIAL_IDENTITY_BOOTSTRAP only. This administrative adapter is
// never imported by installation, cleanup, the broker or the Terraform runner.
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { execFileSync } from "node:child_process";
import { pathToFileURL } from "node:url";
import { cleanSource } from "./component-iam-installation.mjs";
import { buildComponentBrokerPackage } from "./component-broker-package.mjs";
import { authenticateIdentityBootstrapPublication } from "./component-iam-authorization.mjs";
import { executeIdentityBootstrap } from "./component-identity-bootstrap.mjs";
import { authenticateBootstrapOperator } from "./component-bootstrap-operator.mjs";
import { identityBootstrapCapabilitySet } from "./component-installation-identity-contract.mjs";
import { createProductionAwsCredentialEnvironment, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "./production-credential-source-contract.mjs";

const sdk = createRequire(new URL("../../infra/aws/terraform/production-component-deployment-state/broker-package/package.json", import.meta.url));
const administrator = "arn:aws:iam::368992683803:root";
async function administrativeAdapter() {
  let exported;
  const clients = [];
  try {
    exported = JSON.parse(execFileSync("aws", ["configure", "export-credentials", "--format", "process"], {
      env: createProductionAwsCredentialEnvironment({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE, profile: "default", region: "eu-west-2" }),
      encoding: "utf8", stdio: ["ignore", "pipe", "pipe"],
    }));
    const credentials = { accessKeyId: exported.AccessKeyId, secretAccessKey: exported.SecretAccessKey, ...(exported.SessionToken ? { sessionToken: exported.SessionToken } : {}) };
    for (const value of Object.values(credentials)) assert(typeof value === "string" && value);
    const create = (service, className, endpoint, region = "eu-west-2") => {
      const library = sdk(`@aws-sdk/client-${service}`);
      const client = new library[`${className}Client`]({ credentials, region, endpoint, maxAttempts: 1 }); clients.push(client);
      return async (operation, input = {}) => client.send(new library[`${operation}Command`](input));
    };
    const sts = create("sts", "STS", "https://sts.eu-west-2.amazonaws.com");
    const authenticate = async () => {
      const caller = await sts("GetCallerIdentity");
      assert.equal(caller.Account, "368992683803"); assert.equal(caller.Arn, administrator, "First-bootstrap administrator is not the reviewed exact principal");
    };
    await authenticate();
    const permitted = new Set(identityBootstrapCapabilitySet().Statement.flatMap(statement => [].concat(statement.Action)));
    const confined = (service, name, endpoint, region) => {
      const send = create(service, name, endpoint, region);
      return (operation, input) => { assert(permitted.has(`${service}:${service === "s3" && operation === "ListObjectsV2" ? "ListBucket" : operation}`), "Unsupported bootstrap API"); return send(operation, input); };
    };
    const cloudtrail = create("cloudtrail", "CloudTrail", "https://cloudtrail.eu-west-2.amazonaws.com");
    return {
      iam: confined("iam", "IAM", "https://iam.amazonaws.com", "us-east-1"),
      lambda: confined("lambda", "Lambda", "https://lambda.eu-west-2.amazonaws.com"),
      s3: confined("s3", "S3", "https://s3.eu-west-2.amazonaws.com"),
      authenticate,
      async issuanceEvents() {
        const values = new Map(), tokens = new Set(); let NextToken;
        const end = new Date(), start = new Date(end.getTime() - 3600000);
        do {
          const response = await cloudtrail("LookupEvents", { LookupAttributes: [{ AttributeKey: "EventName", AttributeValue: "AssumeRole" }], StartTime: start, EndTime: end, ...(NextToken ? { NextToken } : {}) });
          assert(Array.isArray(response.Events));
          for (const value of response.Events) {
            const event = JSON.parse(value.CloudTrailEvent); assert.equal(event.eventID, value.EventId);
            if (values.has(event.eventID)) assert.deepEqual(values.get(event.eventID), event, "Ambiguous issuance event");
            values.set(event.eventID, event);
          }
          NextToken = response.NextToken;
          if (NextToken) { assert(typeof NextToken === "string" && !tokens.has(NextToken) && tokens.size < 20); tokens.add(NextToken); }
        } while (NextToken);
        return [...values.values()];
      },
      close() { for (const client of clients) client.destroy(); for (const key of Object.keys(credentials)) delete credentials[key]; },
    };
  } catch (error) { for (const client of clients) client.destroy(); throw error; }
  finally { if (exported) for (const field of ["AccessKeyId", "SecretAccessKey", "SessionToken"]) delete exported[field]; }
}

export async function run(argv = process.argv.slice(2), { source = cleanSource, build = buildComponentBrokerPackage,
  authorize = authenticateIdentityBootstrapPublication, admin = administrativeAdapter, human = authenticateBootstrapOperator, execute = executeIdentityBootstrap } = {}) {
  const [mode, runId, transitionId] = argv;
  assert.equal(mode, "execute"); assert.equal(argv.length, 3);
  assert.match(runId || "", /^[1-9][0-9]*$/);
  assert.match(transitionId || "", /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/);
  const sourceSha = source();
  const packageEvidence = await build(); assert.equal(packageEvidence.manifest.sourceSha, sourceSha);
  const approved = authorize({ runId, transitionId, sourceSha }, packageEvidence);
  const { authorizationSha256, ...authorization } = approved;
  assert.equal(source(), sourceSha);
  // Approval is authenticated before either administrative credential loading
  // or human MFA issuance. Root credentials stay only in this adapter's clients.
  const authority = await admin();
  try {
    const operatorProof = await human({ sourceSha, transitionId, authorizationSha256, purpose: "IDENTITY_BOOTSTRAP" }, { issuanceEvents: authority.issuanceEvents });
    const result = await execute({ authorization, packageEvidence, operatorProof }, { ...authority, authenticate: async () => {
      assert.equal(source(), sourceSha, "Protected main moved during bootstrap"); await authority.authenticate();
    } });
    assert.equal(result.state, "BOOTSTRAP_CLOSED");
    return { state: result.state, sourceSha, transitionId, authorizationSha256 };
  } finally { authority.close(); }
}
if (import.meta.url === pathToFileURL(process.argv[1] || "").href) run().then(result => process.stdout.write(`${JSON.stringify(result)}\n`)).catch(() => {
  process.stderr.write("Identity bootstrap rejected; preserve its durable reservation and reconcile exact live targets.\n"); process.exitCode = 1;
});
