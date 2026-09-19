#!/usr/bin/env node
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { cleanSource } from "./component-iam-installation.mjs";
import { establishComponentTerraformSession } from "./component-installation-session.mjs";
import { assertBackend, contract } from "./component-infrastructure-activation.mjs";
import { authenticateHistoricalTerraformActivationAuthorization, authenticatePartialActivationRecoveryAuthorization, readPartialActivationRecoveryEnvironment } from "./component-iam-authorization.mjs";
import { assertPartialActivationRecoveryAuthorization, assertPartialActivationRecoveryEnvironment } from "./component-infrastructure-partial-activation-recovery-authorization.mjs";
import { assertPartialActivationRecoveryPreparation, partialActivationRecoveryTarget } from "./component-infrastructure-partial-activation-recovery-contract.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const sha = bytes => crypto.createHash("sha256").update(bytes).digest("hex");
const uuid = /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const privateBytes = file => { const stat = fs.lstatSync(file); assert(stat.isFile() && stat.nlink === 1 && stat.uid === process.getuid() && (stat.mode & 0o077) === 0 && stat.size > 0 && stat.size <= 1024 * 1024); return fs.readFileSync(file); };

function historical(argv) {
  const [sourceSha, runId, authorizationArtifactSha256, planSha256, preparationSha256, transitionId] = argv;
  assert.match(sourceSha || "", /^[a-f0-9]{40}$/); assert.match(runId || "", /^[1-9][0-9]*$/); assert.match(authorizationArtifactSha256 || "", /^sha256:[a-f0-9]{64}$/);
  for (const value of [planSha256, preparationSha256]) assert.match(value || "", /^[a-f0-9]{64}$/); assert.match(transitionId || "", uuid);
  return { sourceSha, authorizationRunId: runId, authorizationArtifactSha256, planSha256, preparationSha256, transitionId };
}

export async function run(argv = process.argv.slice(2), { source = cleanSource, session = establishComponentTerraformSession,
  historicalAuthorization = authenticateHistoricalTerraformActivationAuthorization, recoveryAuthorization = authenticatePartialActivationRecoveryAuthorization,
  environment = readPartialActivationRecoveryEnvironment, now = Date.now } = {}) {
  const [mode, directory, argument, ...rest] = argv;
  assert(["prepare", "recover"].includes(mode)); assert(path.isAbsolute(directory || ""));
  const work = fs.realpathSync(directory), stat = fs.statSync(work); assert(stat.isDirectory() && stat.uid === process.getuid() && (stat.mode & 0o077) === 0 && work !== root && !work.startsWith(root + "/"));
  const sourceSha = source(); const sourceGuard = () => assert.equal(source(), sourceSha, "Protected source moved");
  const artifactPath = path.join(work, "partial-activation-recovery.json");
  if (mode === "prepare") {
    assert.equal(argv.length, 9); assert(!fs.existsSync(artifactPath), "Use a fresh private recovery directory"); assert.match(argument || "", uuid);
    const historicalActivation = historical(rest); const authenticated = historicalAuthorization({ runId: historicalActivation.authorizationRunId, sourceSha: historicalActivation.sourceSha, transitionId: historicalActivation.transitionId,
      planSha256: historicalActivation.planSha256, preparationSha256: historicalActivation.preparationSha256, authorizationArtifactSha256: historicalActivation.authorizationArtifactSha256 });
    assert.equal(authenticated.historical, true); assert.equal(authenticated.executable, false); sourceGuard();
    const client = await session({ sourceSha, transitionId: historicalActivation.transitionId });
    try {
      const observed = await client.inspectPartialActivationRecovery();
      assert.deepEqual(observed.table, partialActivationRecoveryTarget); assert.equal(observed.iamInstallation.transitionId, historicalActivation.transitionId);
      const preparation = assertPartialActivationRecoveryPreparation({ schemaVersion: 1, sourceSha, recoveryTransitionId: argument, stateIdentity: observed.stateIdentity, backend: contract,
        historicalActivation, iamInstallation: observed.iamInstallation, liveTable: partialActivationRecoveryTarget, lock: observed.lock });
      const bytes = Buffer.from(`${JSON.stringify(preparation, null, 2)}\n`); fs.writeFileSync(artifactPath, bytes, { flag: "wx", mode: 0o600 });
      return { ...preparation, preparationSha256: sha(bytes), historicalAuthorizationExecutable: false };
    } finally { client.close(); }
  }
  assert.equal(argv.length, 3); assert.match(argument || "", /^[1-9][0-9]*$/);
  const bytes = privateBytes(artifactPath), preparationSha256 = sha(bytes), preparation = assertPartialActivationRecoveryPreparation(JSON.parse(bytes));
  assert.equal(preparation.sourceSha, sourceSha); const historicalActivation = preparation.historicalActivation;
  const old = historicalAuthorization({ runId: historicalActivation.authorizationRunId, sourceSha: historicalActivation.sourceSha, transitionId: historicalActivation.transitionId,
    planSha256: historicalActivation.planSha256, preparationSha256: historicalActivation.preparationSha256, authorizationArtifactSha256: historicalActivation.authorizationArtifactSha256 });
  assert.equal(old.historical, true); assert.equal(old.executable, false);
  const approved = recoveryAuthorization({ runId: argument, preparation, preparationSha256 });
  assertPartialActivationRecoveryAuthorization(approved, preparation, preparationSha256, now());
  const settings = environment(sourceSha); assertPartialActivationRecoveryEnvironment(settings.config, settings.branches, [{ state: "approved", user: approved.reviewer, environments: [{ id: settings.config.id, name: approved.environment }] }]);
  sourceGuard();
  const client = await session({ sourceSha, transitionId: historicalActivation.transitionId });
  try {
    let observed, continuation = false;
    try { observed = await client.inspectPartialActivationRecovery(); assert.deepEqual(observed.lock, preparation.lock, "Incident lock changed"); }
    catch { observed = await client.inspectPartialActivationRecoveryContinuation(preparation, preparationSha256); continuation = true; }
    assert.deepEqual(observed.iamInstallation, preparation.iamInstallation, "Component IAM closure changed");
    const authorizationSha256 = sha(Buffer.from(JSON.stringify(approved)));
    if (continuation) assert.notEqual(observed.recovery.authorizationSha256, authorizationSha256, "Recovery authorization already consumed");
    const record = state => ({ schemaVersion: 1, state, sourceSha, recoveryTransitionId: preparation.recoveryTransitionId, preparationSha256,
      authorizationSha256, expiresAt: approved.expiresAt, owner: { principal: client.principal, expiresAt: approved.expiresAt }, historical: historicalActivation, lock: preparation.lock });
    const checkpoint = async (state, continuation) => {
      const value = record(state), etag = await client.beginPartialActivationRecovery(value, preparation, preparationSha256, continuation);
      await client.releasePartialActivationLock(preparation.lock, etag, value, preparation, preparationSha256);
    };
    client.activatePartialActivationRecovery();
    if (continuation && observed.currentRecoveryLock) await client.releasePartialActivationLock(preparation.lock, observed.currentRecoveryLock.etag, observed.recovery, preparation, preparationSha256);
    const result = await client.execute({ mode: continuation && observed.stateExists ? "recover-verify" : "recover", plan: null }, { checkpoint: async value => {
      sourceGuard();
      if (value.stage === "backend") assertBackend(value.backend, value.workspace);
      else if (value.stage === "recovery") await checkpoint("RECOVERY_EXECUTING", continuation);
      else if (value.stage === "adopted") { const state = await client.readRecoveredTerraformState(); assert.deepEqual(state.managedAddresses, [partialActivationRecoveryTarget.address]); await checkpoint("RESOURCE_ADOPTED", true); }
      else if (value.stage === "verified") { await client.readRecoveredTerraformState(); await checkpoint("STATE_VERIFIED", true); }
      else if (value.stage === "closed") await checkpoint("RECOVERY_CLOSED", true);
      else assert.fail("Unexpected recovery checkpoint");
    } });
    assert.deepEqual(result.result, { type: "result", recoveredAddress: partialActivationRecoveryTarget.address, driftVerified: true });
    return { state: "RECOVERY_CLOSED", sourceSha, recoveryTransitionId: preparation.recoveryTransitionId, recoveredAddress: partialActivationRecoveryTarget.address };
  } finally { client.close(); }
}

if (import.meta.url === pathToFileURL(process.argv[1] || "").href) run().then(value => process.stdout.write(`${JSON.stringify(value)}\n`)).catch(() => { process.stderr.write("Component infrastructure partial activation recovery rejected; reconcile exact state before retry.\n"); process.exitCode = 1; });
