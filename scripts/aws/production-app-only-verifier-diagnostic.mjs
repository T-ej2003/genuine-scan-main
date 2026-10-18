import assert from "node:assert/strict";
import { APP_ONLY } from "./production-app-only-contract.mjs";
import { APP_ONLY_VERIFIER } from "./production-app-only-policy.mjs";
import { assertRegisteredAppOnlyVerifier } from "./production-app-only-verifier-command.mjs";
import { assertAppOnlyRequirements } from "./production-app-only-requirements.mjs";
import { authenticateAppOnlyJournalChain } from "./production-app-only-verifier-recovery.mjs";
import { canonicalSha256 } from "./production-green-stage-b-contract.mjs";

const taskPattern = /^arn:aws:ecs:eu-west-2:368992683803:task\/mscqr-prod-euw2-main\/[a-f0-9]{32}$/;
const failurePhases = new Set(["INPUT", "CONFIGURATION", "CATALOGUE", "COMPARISON"]);
const domains = ["DATABASE_SCHEMA", "RLS_FUNCTIONS", "RLS_POLICIES", "RLS_GRANTS", "RLS_FORCE_STATUS", "GENERATED_RLS_CONTRACT"];
const json = (run, args) => JSON.parse(run([...args, "--output", "json", "--no-cli-pager"]));

export function authenticateFailedAppOnlyVerifierTask({ inputs, registration, permission, execution, taskArn,
  run, repositoryRoot }) {
  const { preparation } = inputs;
  assert.match(taskArn || "", taskPattern);
  const sourceSha = preparation.sourceSha, preparationSha256 = preparation.preparationSha256;
  const { preparationSha256: captured, ...body } = preparation;
  assert.equal(captured, canonicalSha256(body));
  assert.equal(preparation.kind, "APP_ONLY_VERIFIER_PREPARATION");
  assert.equal(preparation.identity.sourceSha, sourceSha);
  assert.equal(inputs.kind, "APP_ONLY_VERIFIER_INPUTS"); assert.equal(inputs.schemaVersion, 1);
  assert.equal(preparation.evidence.requirements, inputs.requirements.requirementsSha256);
  assertAppOnlyRequirements(inputs.requirements, { sourceSha,
    candidateSourceSha: preparation.identity.candidateSourceSha, repositoryRoot });
  const registered = authenticateAppOnlyJournalChain(registration, { sourceSha, preparationSha256,
    kind: "APP_ONLY_VERIFIER_REGISTRATION", statuses: ["REGISTRATION_INTENT", "REGISTERED_READBACK_PENDING", "REGISTERED_VERIFIED"] });
  assert.equal(registration[1].event.taskDefinitionArn, registered.event.taskDefinitionArn);
  assert.equal(registered.event.definitionSha256, preparation.definitionSha256);
  assert.equal(registered.event.verificationContractSha256, preparation.verificationContractSha256);
  const permissionSha256 = permission?.[0]?.preparationSha256;
  assert.match(permissionSha256 || "", /^[a-f0-9]{64}$/);
  const permitted = authenticateAppOnlyJournalChain(permission, { sourceSha, preparationSha256: permissionSha256,
    kind: "APP_ONLY_PERMISSION_RESULT", statuses: ["PRE_MUTATION", "PUT_POLICY_INTENT", "VERIFIED"] });
  assert.equal(permitted.event.writesAttempted, 1);
  assert.equal(permitted.event.effective?.verified, true);
  assert.equal(permission[1].event.roleArn, `arn:aws:iam::${APP_ONLY.account}:role/${APP_ONLY_VERIFIER.roleName}`);
  assert.equal(execution?.length, 3, "Incomplete verifier execution journal");
  let previousSha256 = null;
  for (const [index, record] of execution.entries()) {
    const { evidenceSha256, ...recordBody } = record;
    assert.equal(evidenceSha256, canonicalSha256(recordBody));
    assert.equal(recordBody.schemaVersion, 1); assert.equal(recordBody.kind, "APP_ONLY_EXECUTION_JOURNAL");
    assert.equal(recordBody.sourceSha, sourceSha); assert.equal(recordBody.preparationSha256, preparationSha256);
    assert.equal(recordBody.sequence, index + 1); assert.equal(recordBody.previousSha256, previousSha256);
    assert.equal(recordBody.event.kind, "APP_ONLY_VERIFIER_EXECUTION");
    assert.equal(recordBody.event.schemaVersion, 1);
    assert.equal(recordBody.event.status, ["LAUNCH_INTENT", "LAUNCHED", "TASK_OUTCOME_REQUIRES_READBACK"][index]);
    assert.equal(recordBody.event.taskDefinitionArn, registered.event.taskDefinitionArn);
    assert.equal(recordBody.event.verificationContractSha256, preparation.verificationContractSha256);
    assert.equal(recordBody.event.clientToken, canonicalSha256({ sourceSha, preparationSha256 }));
    if (index) assert.equal(recordBody.event.taskArn, taskArn);
    else assert.equal(recordBody.event.taskArn, undefined);
    previousSha256 = evidenceSha256;
  }
  const definition = json(run, ["ecs", "describe-task-definition", "--task-definition", registered.event.taskDefinitionArn, "--include", "TAGS"]);
  assertRegisteredAppOnlyVerifier({ requirements: inputs.requirements, identity: preparation.identity,
    repositoryRoot, databaseSecretArn: preparation.databaseSecretArn,
    taskDefinitionArn: registered.event.taskDefinitionArn,
    definition: { ...definition.taskDefinition, tags: definition.tags || [] } });
  const response = json(run, ["ecs", "describe-tasks", "--cluster", APP_ONLY.clusterArn, "--tasks", taskArn]);
  assert.deepEqual(response.failures || [], []); assert.equal(response.tasks?.length, 1);
  const task = response.tasks[0], container = task.containers?.[0];
  assert.equal(task.taskArn, taskArn); assert.equal(task.clusterArn, APP_ONLY.clusterArn);
  assert.equal(task.taskDefinitionArn, registered.event.taskDefinitionArn);
  assert.equal(task.lastStatus, "STOPPED"); assert.equal(task.stopCode, "EssentialContainerExited");
  assert.equal(task.enableExecuteCommand, false); assert.equal(task.containers?.length, 1);
  assert.equal(container.name, "production-green-read-only-rls-canary");
  assert.equal(container.exitCode, 1); assert.equal(container.imageDigest, preparation.identity.verifierImageDigest);
  const log = definition.taskDefinition.containerDefinitions[0].logConfiguration;
  assert.equal(log.logDriver, "awslogs"); assert.equal(log.options["awslogs-group"], APP_ONLY_VERIFIER.logGroup);
  assert.equal(log.options["awslogs-region"], APP_ONLY.region);
  assert.equal(log.options["awslogs-stream-prefix"], "app-only");
  const stream = `${log.options["awslogs-stream-prefix"]}/${container.name}/${taskArn.split("/").at(-1)}`;
  return { task, stream, logGroup: log.options["awslogs-group"], registrationJournalSha256: registered.evidenceSha256,
    permissionJournalSha256: permitted.evidenceSha256, executionJournalSha256: previousSha256 };
}

export function readFailedAppOnlyVerifierDiagnostic({ run, authenticated, inputs }) {
  const { preparation } = inputs;
  const { task, stream, logGroup } = authenticated;
  assert.match(task.taskArn, taskPattern); assert.equal(task.containers[0].exitCode, 1);
  assert.equal(logGroup, APP_ONLY_VERIFIER.logGroup);
  assert.equal(stream, `app-only/production-green-read-only-rls-canary/${task.taskArn.split("/").at(-1)}`);
  let nextToken, messages = [];
  for (let page = 0; page < 3; page++) {
    const response = json(run, ["logs", "get-log-events", "--log-group-name", logGroup,
      "--log-stream-name", stream, "--start-from-head", "--limit", "2", "--no-paginate",
      ...(nextToken ? ["--next-token", nextToken] : [])]);
    assert.ok(Array.isArray(response.events) && response.events.length <= 2);
    messages.push(...response.events.map(({ message }) => message));
    assert.ok(messages.length <= 1, "Verifier emitted ambiguous output");
    if (!response.nextForwardToken || response.nextForwardToken === nextToken) break;
    assert.ok(page < 2, "Verifier log pagination did not converge");
    nextToken = response.nextForwardToken;
  }
  if (messages.length === 0) throw new Error("Verifier diagnostic is absent");
  assert.equal(messages.length, 1, "Verifier diagnostic is ambiguous");
  assert.ok(typeof messages[0] === "string" && Buffer.byteLength(messages[0]) <= 16384, "Verifier diagnostic is oversized");
  const value = JSON.parse(messages[0]);
  if (value.status === "APP_ONLY_DATABASE_VERIFICATION_FAILED") {
    assert.ok(failurePhases.has(value.phase), "Unknown verifier failure phase");
    assert.deepEqual(Object.keys(value).sort(), ["status", "phase", ...(value.phase === "CATALOGUE" ? ["operation"] : [])].sort());
    if (value.phase === "CATALOGUE") assert.match(value.operation, /^(?:UNKNOWN|[A-Z][A-Z_]{1,79})$/);
    return { verdict: "FAIL", phase: value.phase, operation: value.operation || null, diagnosticSha256: canonicalSha256(value) };
  }
  assert.deepEqual(Object.keys(value).sort(), ["schemaVersion", "kind", "identity", "generatedAt",
    "verificationContractSha256", "requirementsSha256", "domains", "evidenceSha256"].sort());
  assert.equal(value.schemaVersion, 1); assert.equal(value.kind, "APP_ONLY_DATABASE_COMPATIBILITY");
  assert.deepEqual(value.identity, preparation.identity);
  assert.equal(value.verificationContractSha256, preparation.verificationContractSha256);
  assert.equal(value.requirementsSha256, inputs.requirements.requirementsSha256);
  assert.deepEqual(Object.keys(value.domains).sort(), [...domains].sort());
  assert.ok(Object.values(value.domains).every((status) => ["COMPATIBLE", "INCOMPATIBLE", "UNPROVEN"].includes(status)));
  assert.ok(Object.values(value.domains).some((status) => status !== "COMPATIBLE"), "Exit 1 conflicts with compatible output");
  const { evidenceSha256, ...body } = value; assert.equal(evidenceSha256, canonicalSha256(body));
  return { verdict: "FAIL", phase: "COMPARISON", operation: null, domains: value.domains, diagnosticSha256: evidenceSha256 };
}

// ECS can report STOPPED before the awslogs driver delivers its single result.
// Retry only an absent stream event; malformed output and access denials fail closed.
export async function waitForFailedAppOnlyVerifierDiagnostic({ run, authenticated, inputs,
  wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms)), attempts = 12 }) {
  assert.ok(Number.isInteger(attempts) && attempts > 0 && attempts <= 12);
  for (let attempt = 0; attempt < attempts; attempt++) {
    try { return readFailedAppOnlyVerifierDiagnostic({ run, authenticated, inputs }); }
    catch (error) {
      if (error?.message !== "Verifier diagnostic is absent" || attempt === attempts - 1) throw error;
      await wait(5000);
    }
  }
}
