#!/usr/bin/env node
import { verifyHistoricalRuntimeHandoff } from "./verify-production-historical-runtime-handoff.mjs";
import assert from "node:assert/strict";
import { historicalRuntimeRetention as createHistoricalRuntimeRetention, authenticateRetainedHistoricalRuntime, verifyHistoricalRuntimeInventory } from "./production-historical-runtime-evidence.mjs";
import { createAwsReader } from "./production-green-stage-b-ecs-observations.mjs";
import { execFileSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { fileURLToPath, pathToFileURL } from "node:url";
import { advanceProductionComponentDeploymentStateWithRetry, createProductionComponentDeploymentStateClient, PRODUCTION_COMPONENT_STATE, stateHash } from "./production-component-deployment-state.mjs";
import { canonicalSha256 } from "./production-green-stage-b-contract.mjs";
import { assertImageAuthorization, authorizedBackendDigest } from "./production-cutover-control-plane.mjs";
import { assertProductionRlsReleaseReceipt, assertNormalBackendActivationEvidence } from "./production-normal-backend-activation.mjs";
import { createAppOnlyEcsReaders } from "./production-app-only-adapters.mjs";
import { captureAppOnlyPredecessor } from "./production-app-only-contract.mjs";
import { serviceDefinition } from "./bootstrap-production-component-deployment-state.mjs";
import { WEB_RELEASE, assertCoordinatedImageAuthorization } from "./production-web-release-contract.mjs";
import { createPinnedRootAttestationVerifier } from "./production-root-attestation-key.mjs";
import { assertGithubOidcReleaseDeployerEnvironment, createProductionAwsCommandRunner, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "./production-credential-source-contract.mjs";
import { assertStagedBrokerProof, assertStagedBrokerTerminal, readStagedBrokerClosure } from "./stage-b-staged-broker-closure.mjs";
import { deriveStageBToolingInputTreeSha256 } from "./validate-stage-b-image-reuse.mjs";
import { readStageBProtectedMainCheckout } from "./stage-b-deployment-identity.mjs";
import {createReleaseCoordinatorStore} from './production-release-evidence-store.mjs';
import {ensureStageBPrivateDirectory} from './stage-b-artifact-contract.mjs';
import {componentCommitOperationId,journalComponentCommit,matchesCommittedReleaseState} from './production-release-gate-component-journal.mjs';

const SHA = /^[a-f0-9]{40}$/;
const HASH = /^[a-f0-9]{64}$/;

export function commitSecurityComponentState(options = {}) {
  if (!options.stagedBrokerProof) return commitSecurityState(options);
  const proof = options.stagedBrokerProof; assertStagedBrokerProof(proof, options.sourceSha);
  return (async () => {
    await proof.revalidate();
    const { previousGeneration, ...result } = commitSecurityState(options);
    await proof.revalidate();
    return { ...result, stagedBroker: assertStagedBrokerTerminal(proof, { client: options.client, result, previousGeneration }) };
  })();
}
function commitSecurityState({ sourceSha, authorization, webAuthorization, verifyWeb = createPinnedRootAttestationVerifier(), releaseReceipt, backendActivation, backendLive, backendImageSource, frontendActivation, frontendLive, frontendImageSource, client, historicalRuntimeEvidence, runtimeReader, verifyRuntimeSignature, historicalRuntimeRequired = false, now, isProtectedMainAncestor = () => true, writerContext, stagedBrokerProof } = {}) {
  assert.match(sourceSha || "", SHA); assert.match(authorization?.sourceSha || "", SHA); assert.equal(authorization.sourceSha, sourceSha);
  assert.match(authorization.authorizationSha256 || "", HASH); assert.equal(canonicalSha256((({ authorizationSha256, ...body }) => body)(authorization)), authorization.authorizationSha256, "Security authorization integrity is invalid");
  assert.equal(isProtectedMainAncestor(sourceSha), true, "Security release source is not protected-main history.");
  const current = client.read(); assert.ok(current, "Production component deployment state is not bootstrapped.");
  if (runtimeReader) verifyHistoricalRuntimeHandoff({ evidence: historicalRuntimeEvidence, state: current, reader: runtimeReader, sourceSha, verify: verifyRuntimeSignature, now });
  let retention = current.historicalRuntimeRetention;
  if (retention) {
    authenticateRetainedHistoricalRuntime({ state: current, reader: runtimeReader, verify: verifyRuntimeSignature });
    verifyHistoricalRuntimeInventory({ reference: retention.reference, reader: runtimeReader });
  }
  if (historicalRuntimeRequired && !retention) assert.ok(historicalRuntimeEvidence, "Release closure omitted the required authenticated historical runtime handoff");
  if (historicalRuntimeEvidence) {
    retention = createHistoricalRuntimeRetention({ evidence: historicalRuntimeEvidence, sourceSha, current, componentStateSha256: stateHash(current), reader: runtimeReader, verify: verifyRuntimeSignature, writerContext, now });
    verifyHistoricalRuntimeInventory({ reference: retention.reference, reader: runtimeReader });
  }
  const changes = { security: { sourceSha, releaseIdentity: authorization.authorizationSha256 } };
  if (stagedBrokerProof) { assertStagedBrokerProof(stagedBrokerProof, sourceSha); changes.security.stagedBrokerEvidenceSha256 = stagedBrokerProof.evidenceSha256; }
  if (releaseReceipt || backendActivation || backendLive || backendImageSource) {
    assert.ok(releaseReceipt && backendActivation && backendLive && backendImageSource, "Security terminal live component evidence is incomplete.");
    assertImageAuthorization(authorization, sourceSha); assertProductionRlsReleaseReceipt(releaseReceipt, { sourceSha, imageDigest: authorizedBackendDigest(authorization) });
    assertNormalBackendActivationEvidence(backendActivation, { sourceSha, stageBAuthorization: authorization });
    assert.equal(backendActivation.imageDigest, backendLive.backendDigest); assert.equal(backendActivation.targetArn, backendLive.taskDefinitionArn); assert.equal(backendActivation.desiredCount, backendLive.desiredCount);
    assert.match(backendImageSource, SHA); assert.equal(isProtectedMainAncestor(backendImageSource), true, "Live backend source is not protected-main history.");
    changes.database = { sourceSha, releaseIdentity: releaseReceipt.receiptBundleSha256 };
    changes.backend = { sourceSha: backendImageSource, establishedThroughSha: sourceSha, imageDigest: backendLive.backendDigest, taskDefinitionArn: backendLive.taskDefinitionArn, desiredCount: backendLive.desiredCount };
  }
  const frontendInputs = [frontendActivation, frontendLive, frontendImageSource];
  const webRequired = authorization.imageReuseEvidence?.webPublicationRequired || Boolean(frontendActivation);
  assert.equal(frontendInputs.some(Boolean), frontendInputs.every(Boolean), "Frontend terminal live component evidence is incomplete.");
  if (webRequired === true) assert.equal(frontendInputs.every(Boolean), true, "Web-required security release did not provide frontend terminal evidence.");
  if (frontendActivation && authorization.imageReuseEvidence?.webPublicationRequired === false) {
    assert.ok(webAuthorization, "Frontend activation without a new build requires signed web authorization.");
    assertCoordinatedImageAuthorization({ sourceSha, stageBAuthorization: authorization, webAuthorization,
      webPublicationRequired: false, verifyWeb, now });
    assert.equal(webAuthorization.imageRef, frontendActivation.imageRef, "Frontend activation differs from signed web image.");
  }
  if (frontendInputs.every(Boolean)) {
    assert.equal(webRequired, true, "Frontend state may change only for an authenticated web activation.");
    assert.equal(frontendActivation.sourceSha, sourceSha); assert.match(frontendActivation.candidateTaskDefinitionArn || "", /^arn:aws:ecs:eu-west-2:368992683803:task-definition\/mscqr-frontend:[1-9][0-9]*$/); assert.match(frontendActivation.imageRef || "", /^368992683803\.dkr\.ecr\.eu-west-2\.amazonaws\.com\/mscqr-web@sha256:[a-f0-9]{64}$/); assert.equal(frontendActivation.health?.ready, true); assert.equal(frontendActivation.health?.loginStatus, 200);
    assert.equal(frontendLive.sourceSha, frontendImageSource); assert.equal(frontendLive.sourceSha, sourceSha); assert.equal(frontendLive.imageDigest, frontendActivation.imageRef.split("@")[1]); assert.equal(frontendLive.taskDefinitionArn, frontendActivation.candidateTaskDefinitionArn); assert.equal(frontendLive.desiredCount, 2);
    changes.frontend = { ...frontendLive, establishedThroughSha: sourceSha };
  }
  if (retention) verifyHistoricalRuntimeInventory({ reference: retention.reference, reader: runtimeReader });
  const result = advanceProductionComponentDeploymentStateWithRetry({ client, current, ...(retention ? { historicalRuntimeRetention: retention, maxRetries: 0 } : {}), ...(stagedBrokerProof ? { maxRetries: 0 } : {}), lane: "SECURITY_INFRASTRUCTURE", changes, ...writerContext });
  if (retention) verifyHistoricalRuntimeInventory({ reference: retention.reference, reader: runtimeReader });
  return stagedBrokerProof ? { ...result, previousGeneration: current.generation } : result;
}

async function main() {
  const values = Object.fromEntries(process.argv.slice(2).map((value) => value.split("=", 2)).filter(([key, value]) => key && value).map(([key, value]) => [key.replace(/^--/, ""), value]));
  const historical = values["historical-runtime-evidence"] !== undefined || values["historical-runtime-evidence-sha256"] !== undefined;
  const historicalOptions = historical ? ["historical-runtime-evidence", "historical-runtime-evidence-sha256"] : [];
  const frontend = values["frontend-activation"] !== undefined || values["frontend-activation-sha256"] !== undefined;
  const web = values["web-authorization"] !== undefined || values["web-authorization-sha256"] !== undefined;
  assert.deepEqual(Object.keys(values).sort(), [...historicalOptions, "authorization", "authorization-sha256", "backend-metadata", "backend-metadata-sha256", "release-receipt", "release-receipt-sha256", "source-sha", ...(frontend ? ["frontend-activation", "frontend-activation-sha256"] : []), ...(web ? ["web-authorization", "web-authorization-sha256"] : [])].sort()); assert.match(values["source-sha"], SHA); for (const name of [...(historical ? ["historical-runtime-evidence-sha256"] : []), "authorization-sha256", "backend-metadata-sha256", "release-receipt-sha256", ...(frontend ? ["frontend-activation-sha256"] : []), ...(web ? ["web-authorization-sha256"] : [])]) assert.match(values[name], HASH); for (const name of [...(historical ? ["historical-runtime-evidence"] : []), "authorization", "backend-metadata", "release-receipt", ...(frontend ? ["frontend-activation"] : []), ...(web ? ["web-authorization"] : [])]) assert.ok(path.isAbsolute(values[name]));
  const bytes = fs.readFileSync(values.authorization); assert.equal(crypto.createHash("sha256").update(bytes).digest("hex"), values["authorization-sha256"], "Security authorization file hash is invalid.");
  const readBoundJson = (file, expected, label) => { const value = fs.readFileSync(file); assert.equal(crypto.createHash("sha256").update(value).digest("hex"), expected, `${label} file hash is invalid.`); return JSON.parse(value); };
  const authorization = JSON.parse(bytes), releaseReceipt = readBoundJson(values["release-receipt"], values["release-receipt-sha256"], "Production RLS receipt"), backendActivation = readBoundJson(values["backend-metadata"], values["backend-metadata-sha256"], "Backend activation metadata"), frontendActivation = frontend ? readBoundJson(values["frontend-activation"], values["frontend-activation-sha256"], "Frontend activation") : undefined,
    webAuthorization = web ? readBoundJson(values["web-authorization"], values["web-authorization-sha256"], "Web authorization") : undefined; assertGithubOidcReleaseDeployerEnvironment();
  assert.match(process.env.GITHUB_WORKFLOW_REF || "", /^T-ej2003\/genuine-scan-main\/.github\/workflows\/release-gate\.yml@refs\/heads\/main$/); assert.match(process.env.GITHUB_RUN_ID || "", /^[1-9][0-9]*$/);
  const run = createProductionAwsCommandRunner({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.GITHUB_OIDC_RELEASE_DEPLOYER, region: PRODUCTION_COMPONENT_STATE.region });
  const caller = JSON.parse(run(["sts", "get-caller-identity", "--output", "json", "--no-cli-pager"])); assert.equal(String(caller.Account), PRODUCTION_COMPONENT_STATE.account); assert.match(caller.Arn || "", /^arn:aws:sts::368992683803:assumed-role\/mscqr-production-release-deployer\/[^/]+$/);
  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
  const readers = createAppOnlyEcsReaders(run); const backendLive = captureAppOnlyPredecessor(readers.readLive()); const backendImageSource = readers.readBackendImageSource(backendLive.backendDigest); const frontendLive = frontend ? serviceDefinition(run, WEB_RELEASE.cluster, WEB_RELEASE.serviceName, WEB_RELEASE.family, WEB_RELEASE.container, `368992683803.dkr.ecr.eu-west-2.amazonaws.com/${WEB_RELEASE.repository}`) : undefined;
  const runtimeReader = createAwsReader({ region: PRODUCTION_COMPONENT_STATE.region, clusterArn: "arn:aws:ecs:eu-west-2:368992683803:cluster/mscqr-prod-euw2-main", run });
  const allTasks = runtimeReader.listTasks("RUNNING");
  let historicalRuntimeRequired = false;
  for (let i = 0; i < allTasks.length; i += 100) {
    const described = runtimeReader.describeTasks(allTasks.slice(i, i + 100)); assert.equal(described.failures?.length, 0); assert.equal(described.tasks?.length, allTasks.slice(i, i + 100).length);
    historicalRuntimeRequired ||= described.tasks.some((task) => task.taskDefinitionArn?.includes(":task-definition/mscqr-production-rls-green-worker-candidate:"));
  }
  const historicalRuntimeEvidence = historical ? readBoundJson(values["historical-runtime-evidence"], values["historical-runtime-evidence-sha256"], "Historical runtime evidence") : undefined;
  const stagedBrokerProof = await readStagedBrokerClosure({ sourceSha: values["source-sha"], run, readCheckout: () => {
    const checkout = readStageBProtectedMainCheckout({ cwd: root, fetchOriginMain: true, requireCanonicalRepository: true });
    return { sourceSha: checkout.currentHead, treeSha256: deriveStageBToolingInputTreeSha256(checkout.currentHead) };
  } });
  const client=createProductionComponentDeploymentStateClient({run});
  const commit=()=>commitSecurityComponentState({ stagedBrokerProof, historicalRuntimeRequired, historicalRuntimeEvidence, runtimeReader, sourceSha: values["source-sha"], authorization, webAuthorization, releaseReceipt, backendActivation, backendLive, backendImageSource, frontendActivation, frontendLive, frontendImageSource: frontendLive?.sourceSha, client, writerContext: { updatedByWorkflow: process.env.GITHUB_WORKFLOW_REF, githubRunId: process.env.GITHUB_RUN_ID }, isProtectedMainAncestor: (sourceSha) => {
    try { execFileSync("git", ["merge-base", "--is-ancestor", sourceSha, "refs/remotes/origin/main"], { cwd: root, stdio: "ignore" }); return true; } catch { return false; }
  } });
  let result;
  if(process.env.ROTATION_ID&&process.env.RELEASE_TRAIN_RUN_ID){
    const operationId=componentCommitOperationId({sourceSha:values['source-sha'],rotationId:process.env.ROTATION_ID,
      releaseTrainRunId:process.env.RELEASE_TRAIN_RUN_ID,authorizationSha256:authorization.authorizationSha256});
    const directory=path.join(os.tmpdir(),`mscqr-component-journal-${process.pid}`);
    ensureStageBPrivateDirectory({directory,repositoryRoot:root,create:true});
    const store=createReleaseCoordinatorStore({run,directory,repositoryRoot:root});
    const intent={operationId,sourceSha:values['source-sha'],rotationId:process.env.ROTATION_ID,
      releaseTrainRunId:process.env.RELEASE_TRAIN_RUN_ID,childRunId:process.env.GITHUB_RUN_ID,
      authorizationSha256:authorization.authorizationSha256,rlsReceiptSha256:releaseReceipt.receiptBundleSha256,
      backendTaskDefinitionArn:backendActivation.targetArn,backendImageDigest:backendActivation.imageDigest,
      ...(frontendActivation?{frontendTaskDefinitionArn:frontendActivation.candidateTaskDefinitionArn,
        frontendImageDigest:frontendActivation.imageRef.split('@')[1]}:{})};
    if(stagedBrokerProof)await stagedBrokerProof.revalidate();
    result=await journalComponentCommit({store,operationId,intent,readState:()=>client.read(),commit,
      verifyCommitted:state=>matchesCommittedReleaseState({state,sourceSha:values['source-sha'],
        authorizationSha256:authorization.authorizationSha256,rlsReceipt:releaseReceipt,backendActivation,frontendActivation,
        childRunId:process.env.GITHUB_RUN_ID,webRequired:authorization.imageReuseEvidence?.webPublicationRequired===true || Boolean(frontendActivation)})});
    if(stagedBrokerProof)await stagedBrokerProof.revalidate();
  }else result=await commit();
  process.stdout.write(`${JSON.stringify({ generation: result.state.generation, component: "security", sourceSha: result.state.components.security.sourceSha })}\n`);
}

if (process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url) main().catch(error => { console.error(error.message); process.exitCode = 1; });
