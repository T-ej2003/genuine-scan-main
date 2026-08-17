import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { assertStageBPlan, assertStageBPlanCapture } from "../plan-production-green-stage-b.mjs";
import { assertStageBBrokerAliasArn, assertStageBBrokerConfigurationIdentity, STAGE_B, STAGE_B_MODES } from "../aws/production-green-stage-b-contract.mjs";
import {
  createAwsReader,
  generateReferenceAudit,
  batch,
  parseCli,
} from "../aws/generate-production-green-stage-b-reference-audit.mjs";
import {
  assertStageBAtomicBrokerPlan,
  assertStageBAtomicBrokerPackagePlan,
  assertStageBActiveBrokerTaskDefinitionLocal,
  assertStageBBrokerTaskDefinitionMapping,
  assertTerraformDependencyCoversAddress,
  STAGE_B_REFERENCE_AUDIT_CLOCK_SKEW_MS,
  STAGE_B_REFERENCE_AUDIT_MAX_AGE_MS,
  STAGE_B_EXECUTOR_FOR_EACH_REFERENCES,
  STAGE_B_CANDIDATE_FOR_EACH_REFERENCES,
  STAGE_B_BROKER_TASK_DEFINITION_REFERENCE,
  STAGE_B_ACTIVE_BROKER_TASK_DEFINITION_LOCAL_EXPRESSION,
  STAGE_B_TASK_DEFINITION_FAMILIES,
} from "../aws/stage-b-reference-audit-contract.mjs";
import { assertStageBFreshImageReferenceAuditBinding } from "../aws/stage-b-plan-approval-contract.mjs";

const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const planSha256 = "a".repeat(64);
const packageBytes = Buffer.from("stage-b-broker-zip-fixture-v1");
const packageChecksum = sha256(Buffer.from("stage-b-full-rls-release-package-fixture-v1"));
const brokerZipFileSha256 = sha256(packageBytes);
const packageSourceCodeHash = crypto.createHash("sha256").update(packageBytes).digest("base64");
const releaseSha = "a".repeat(40);
const sourceContractSha256 = "b".repeat(64);
const migrationSetDigest = "c".repeat(64);
const imageFor = (name) => `368992683803.dkr.ecr.eu-west-2.amazonaws.com/${name}@sha256:${"d".repeat(64)}`;
const packageDirectory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-stage-b-audit-"));
const packagePath = path.join(packageDirectory, "broker.zip");
fs.writeFileSync(packagePath, packageBytes, { mode: 0o600 });
const callerArn = "arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/test-session";
const brokerAliasArn = STAGE_B.brokerAliasArn;
const clusterArn = "arn:aws:ecs:eu-west-2:368992683803:cluster/mscqr-prod-euw2-main";
const now = new Date("2026-07-31T14:05:00.000Z");
const terraformConfigurationSource = fs.readFileSync("infra/aws/terraform/production-green-stage-b/main.tf", "utf8");
const oldArnFor = (family) => `arn:aws:ecs:eu-west-2:368992683803:task-definition/${family}:1`;
const newArnFor = (family) => `arn:aws:ecs:eu-west-2:368992683803:task-definition/${family}:2`;
const backendAddress = 'aws_ecs_task_definition.candidate["backend"]';
const canaryAddress = 'aws_ecs_task_definition.candidate["canary"]';
const readOnlyCanaryAddress = 'aws_ecs_task_definition.candidate["read_only_canary"]';
const executorCollectionAddress = "aws_ecs_task_definition.executor";
const readOnlyCanaryFamily = STAGE_B_TASK_DEFINITION_FAMILIES[readOnlyCanaryAddress];
const historyGeneration = "aaaaaaaa";
const retainedAddressFor = (address, generation = historyGeneration) => {
  const match = /^(aws_ecs_task_definition\.(candidate|executor))\["([^"]+)"\]$/.exec(address);
  return `${match[1]}_retained["${generation}-${match[3]}"]`;
};
const executorAddressForMode = (mode) => `${executorCollectionAddress}["${mode}"]`;
const taskDefinitionAddressForMode = (mode) => mode === "full-rls-application-canary" ? canaryAddress : executorAddressForMode(mode);
const familyForMode = (mode) => mode === "full-rls-application-canary"
  ? STAGE_B_TASK_DEFINITION_FAMILIES['aws_ecs_task_definition.candidate["canary"]']
  : `mscqr-production-full-rls-green-${mode}`;
const rotationDefinitionFor = (address, family, index) => {
  const key = /\["([^\"]+)"\]$/.exec(address)?.[1];
  const executor = address.startsWith(executorCollectionAddress);
  const imageVariable = executor ? "executor_image" : `${key}_image`;
  const environmentNames = executor
    ? ["RELEASE_GIT_SHA", "MSCQR_FULL_RLS_SOURCE_CONTRACT_SHA256", "MSCQR_FULL_RLS_MIGRATION_SET_DIGEST", "MSCQR_FULL_RLS_PACKAGE_CHECKSUM_SHA256"]
    : key === "canary" ? ["RELEASE_GIT_SHA", "MSCQR_FULL_RLS_SOURCE_CONTRACT_SHA256", "MSCQR_FULL_RLS_MIGRATION_SET_DIGEST"]
      : key === "read_only_canary" ? [] : ["RELEASE_GIT_SHA"];
  const environmentVariables = new Map([
    ["RELEASE_GIT_SHA", releaseSha],
    ["MSCQR_FULL_RLS_SOURCE_CONTRACT_SHA256", sourceContractSha256],
    ["MSCQR_FULL_RLS_MIGRATION_SET_DIGEST", migrationSetDigest],
    ["MSCQR_FULL_RLS_PACKAGE_CHECKSUM_SHA256", packageChecksum],
  ]);
  const container = {
    name: executor ? "production-rls-executor" : key === "canary" ? "production-green-canary" : key === "read_only_canary" ? "production-green-read-only-rls-canary" : key,
    image: `368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@sha256:${"e".repeat(64)}`,
    environment: environmentNames.map((name) => ({ name, value: `old-${name}` })),
  };
  const afterContainer = { ...container, image: imageFor(imageVariable === "worker_image" ? "mscqr-worker" : "mscqr-backend"), environment: environmentNames.map((name) => ({ name, value: environmentVariables.get(name) })) };
  const stable = {
    family,
    network_mode: "awsvpc",
    requires_compatibilities: ["FARGATE"],
    cpu: key === "worker" ? "512" : key === "read_only_canary" ? "256" : "1024",
    memory: key === "worker" ? "1024" : key === "read_only_canary" ? "512" : "2048",
    execution_role_arn: "arn:aws:iam::368992683803:role/mscqr-production-full-rls-green-executor-execution",
    task_role_arn: "arn:aws:iam::368992683803:role/mscqr-production-full-rls-green-executor-task",
    runtime_platform: { operating_system_family: "LINUX", cpu_architecture: "X86_64" },
    volume: [],
    ipc_mode: "",
    pid_mode: "",
    tags: { Environment: "production", ManagedBy: "Terraform", Component: "full-rls-green-stage-b" },
  };
  return {
    before: { ...stable, arn: oldArnFor(family), container_definitions: JSON.stringify([container]) },
    after: { ...stable, arn: newArnFor(family), container_definitions: JSON.stringify([afterContainer]) },
  };
};

function makeFixture({ mutatePlan, mutateReader, packageValue = packageChecksum, terraformConfiguration = terraformConfigurationSource, appendOnly = false } = {}) {
  let changes = Object.entries(STAGE_B_TASK_DEFINITION_FAMILIES).map(([address, family]) => ({
    address,
    mode: "managed",
    type: "aws_ecs_task_definition",
    change: {
      actions: ["delete", "create"],
      ...rotationDefinitionFor(address, family, 1),
      replace_paths: [["container_definitions"]],
    },
  }));
  if (appendOnly) {
    const current = changes.map((change) => ({ ...change, change: { ...change.change, actions: ["create"], before: null, after: { ...change.change.after, arn: newArnFor(change.change.after.family) }, replace_paths: undefined } }));
    const retained = changes.filter(({ address }) => address !== readOnlyCanaryAddress).map((change) => {
      const retainedAddress = retainedAddressFor(change.address);
      return { ...change, address: retainedAddress, change: { actions: ["no-op"], before: change.change.before, after: change.change.after } };
    });
    changes = [...current, ...retained];
  }
  const plan = {
    variables: {
      package_checksum_sha256: { value: packageChecksum },
      broker_package_path: { value: packagePath },
      tooling_sha: { value: "e".repeat(40) },
      image_release_sha: { value: releaseSha },
      canonical_image_evidence_sha256: { value: "f".repeat(64) },
      source_contract_sha256: { value: sourceContractSha256 },
      migration_set_digest: { value: migrationSetDigest },
      backend_image: { value: imageFor("mscqr-backend") },
      worker_image: { value: imageFor("mscqr-worker") },
      executor_image: { value: imageFor("mscqr-backend") },
      canary_image: { value: imageFor("mscqr-backend") },
      read_only_canary_image: { value: imageFor("mscqr-backend") },
    },
    resource_changes: changes,
  };
  mutatePlan?.(plan);
  if (!plan.planned_values) {
    plan.planned_values = { root_module: { resources: plan.resource_changes.filter((item) => item.type === "aws_ecs_task_definition").map((item) => ({ address: item.address, type: item.type, index: item.address.match(/\["([^\"]+)"\]$/)?.[1], values: item.change.after })) } };
  }
  plan.prior_state = { format_version: "1.0", terraform_version: "1.15.8", values: { root_module: { resources: plan.resource_changes.filter((item) => item.type === "aws_ecs_task_definition" && item.change.before).map((item) => ({ address: item.address, mode: "managed", type: item.type, name: item.address, values: item.change.before })) } } };
  const planBytes = Buffer.from(JSON.stringify(plan));
  const actualPlanSha = sha256(planBytes);
  const brokerTaskDefinitions = Object.fromEntries(STAGE_B_MODES.map((mode) => {
    const family = familyForMode(mode);
    return [mode, appendOnly ? oldArnFor(family) : newArnFor(family)];
  }));
  const baseConfig = {
    FunctionArn: STAGE_B.brokerFunctionArn,
    Version: "2",
    Environment: {
      Variables: {
        BROKER_TASK_DEFINITIONS_JSON: JSON.stringify(brokerTaskDefinitions),
        BROKER_APPROVAL_EXPECTED_JSON: JSON.stringify({ packageChecksumSha256: packageValue }),
      },
    },
  };
  const baseAlias = {
    AliasArn: STAGE_B.brokerAliasArn,
    Name: STAGE_B.brokerAliasQualifier,
    FunctionVersion: "2",
  };
  const reader = {
    getCallerIdentity: () => ({ Arn: callerArn }),
    listServices: () => [],
    describeServices: () => ({ services: [], failures: [] }),
    listTasks: () => [],
    describeTasks: () => ({ tasks: [], failures: [] }),
    describeTaskDefinition: (reference) => {
      const family = reference.includes("task-definition/") ? reference.split("task-definition/")[1].replace(/:[0-9]+$/, "") : reference;
      const revision = reference.includes(":1") ? 1 : 2;
      return { taskDefinition: { taskDefinitionArn: `arn:aws:ecs:eu-west-2:368992683803:task-definition/${family}:${revision}`, family, revision, status: "ACTIVE" } };
    },
    getFunctionConfiguration: () => structuredClone(baseConfig),
    getAlias: () => structuredClone(baseAlias),
  };
  mutateReader?.(reader);
  return {
    plan,
    planBytes,
    planJsonSha256: actualPlanSha,
    reader,
    options: {
      region: "eu-west-2",
      clusterArn,
      brokerAliasArn,
      expectedPackageChecksumSha256: packageChecksum,
      callerArn,
      terraformConfiguration,
      auditedAt: "2026-07-31T14:00:00.000Z",
      now,
    },
  };
}

function makeCurrentRetainedPredecessorFixture({ currentRevision = 5, retainedRevision = 4, mutatePlan } = {}) {
  return makeAtomicBrokerFixture({
    appendOnly: false,
    mutatePlan: (plan) => {
      const currentChanges = plan.resource_changes.filter((item) => Object.hasOwn(STAGE_B_TASK_DEFINITION_FAMILIES, item.address));
      for (const change of currentChanges) {
        if (change.address !== canaryAddress) continue;
        const family = STAGE_B_TASK_DEFINITION_FAMILIES[change.address];
        change.change.before.arn = `arn:aws:ecs:eu-west-2:368992683803:task-definition/${family}:${currentRevision}`;
        change.change.after.arn = `arn:aws:ecs:eu-west-2:368992683803:task-definition/${family}:${currentRevision + 1}`;
        plan.resource_changes.push({
          address: retainedAddressFor(change.address, "bbbbbbbb"),
          mode: "managed",
          type: "aws_ecs_task_definition",
          change: { actions: ["no-op"], before: { family, arn: `arn:aws:ecs:eu-west-2:368992683803:task-definition/${family}:${retainedRevision}` }, after: { family } },
        });
      }
      mutatePlan?.(plan);
    },
    mutateReader: (reader) => {
      const originalDescribe = reader.describeTaskDefinition;
      reader.describeTaskDefinition = (reference) => {
        const response = originalDescribe(reference);
        const match = /:([1-9][0-9]*)$/.exec(reference);
        if (match) response.taskDefinition.revision = Number(match[1]);
        response.taskDefinition.taskDefinitionArn = reference;
        return response;
      };
      const originalConfiguration = reader.getFunctionConfiguration;
      reader.getFunctionConfiguration = () => {
        const configuration = originalConfiguration();
        const taskDefinitions = JSON.parse(configuration.Environment.Variables.BROKER_TASK_DEFINITIONS_JSON);
        taskDefinitions["full-rls-application-canary"] = `arn:aws:ecs:eu-west-2:368992683803:task-definition/${familyForMode("full-rls-application-canary")}:${currentRevision}`;
        configuration.Environment.Variables.BROKER_TASK_DEFINITIONS_JSON = JSON.stringify(taskDefinitions);
        return configuration;
      };
    },
  });
}

function makeAppendOnlyCurrentPredecessorFixture() {
  const currentArn = oldArnFor(STAGE_B_TASK_DEFINITION_FAMILIES[canaryAddress]).replace(":1", ":5");
  return makeAtomicBrokerFixture({
    appendOnly: true,
    mutatePlan: (plan) => {
      const current = plan.resource_changes.find((item) => item.address === canaryAddress);
      const retained = plan.resource_changes.find((item) => item.address === retainedAddressFor(canaryAddress));
      current.change = {
        ...current.change,
        actions: ["delete", "create"],
        before: { ...retained.change.before, arn: oldArnFor(STAGE_B_TASK_DEFINITION_FAMILIES[canaryAddress]).replace(":1", ":5") },
        after: { ...current.change.after, arn: newArnFor(STAGE_B_TASK_DEFINITION_FAMILIES[canaryAddress]).replace(":2", ":6") },
        replace_paths: [["container_definitions"]],
      };
      retained.change.before.arn = oldArnFor(STAGE_B_TASK_DEFINITION_FAMILIES[canaryAddress]).replace(":1", ":4");
    },
    mutateReader: (reader) => {
      const original = reader.getFunctionConfiguration;
      reader.getFunctionConfiguration = () => {
        const configuration = original();
        const taskDefinitions = JSON.parse(configuration.Environment.Variables.BROKER_TASK_DEFINITIONS_JSON);
        taskDefinitions["full-rls-application-canary"] = currentArn;
        configuration.Environment.Variables.BROKER_TASK_DEFINITIONS_JSON = JSON.stringify(taskDefinitions);
        return configuration;
      };
    },
  });
}

function generate(fixture, overrides = {}) {
  return generateReferenceAudit({
    plan: fixture.plan,
    planBytes: fixture.planBytes,
    planJsonSha256: fixture.planJsonSha256,
    reader: fixture.reader,
    ...fixture.options,
    ...overrides,
  });
}

function validateBrokerPlan(fixture, audit) {
  const auditBytes = Buffer.from(JSON.stringify(audit));
  assert.doesNotThrow(() => assertStageBPlan(fixture.plan, {
    referenceAudit: audit,
    referenceAuditBytes: auditBytes,
    referenceAuditSha256: sha256(auditBytes),
    planJsonBytes: fixture.planBytes,
    planJsonSha256: fixture.planJsonSha256,
    terraformConfiguration: fixture.options.terraformConfiguration,
    trustedCallerArn: callerArn,
    now,
  }));
}

function makeCreateOnlyFixture({ mutatePlan, mutateReader, appendOnly = false } = {}) {
  const build = appendOnly ? makeAtomicBrokerFixture : makeFixture;
  return build({
    appendOnly,
    mutatePlan: (plan) => {
      const change = plan.resource_changes.find((item) => item.address === readOnlyCanaryAddress);
      change.change.actions = ["create"];
      change.change.before = null;
      delete change.change.replace_paths;
      mutatePlan?.(plan);
    },
    mutateReader,
  });
}

function addBrokerAtomicPlanContract(plan, taskDefinitionAddress = canaryAddress, relevantAddress = taskDefinitionAddress, { omitExecutorCollectionDependency = false } = {}) {
  const executorTarget = taskDefinitionAddress.startsWith(`${executorCollectionAddress}[`);
  plan.configuration = {
    root_module: {
      resources: [
        {
          address: "aws_lambda_function.broker",
          type: "aws_lambda_function",
          expressions: {
            environment: [{ variables: { references: [STAGE_B_BROKER_TASK_DEFINITION_REFERENCE, "local.broker_approval_expected"] } }],
            filename: { references: ["var.broker_package_path"] },
            source_code_hash: { references: ["var.broker_package_path"] },
          },
        },
        {
          address: executorCollectionAddress,
          type: "aws_ecs_task_definition",
          for_each_expression: { references: [...STAGE_B_EXECUTOR_FOR_EACH_REFERENCES] },
          expressions: { family: { references: ["each.value.family"] } },
        },
        {
          address: "aws_ecs_task_definition.candidate",
          type: "aws_ecs_task_definition",
          for_each_expression: { references: [...STAGE_B_CANDIDATE_FOR_EACH_REFERENCES] },
          expressions: { family: { references: ["each.value.family"] } },
        },
      ],
    },
  };
  plan.planned_values = {
    root_module: {
      resources: Object.entries(STAGE_B_TASK_DEFINITION_FAMILIES).map(([address, family]) => ({
        address,
        type: "aws_ecs_task_definition",
        index: address.match(/\["([^"]+)"\]$/)?.[1],
        values: { family },
        identity: { family },
      })),
    },
  };
  plan.relevant_attributes = executorTarget
    ? (omitExecutorCollectionDependency ? [] : [{ resource: executorCollectionAddress, attribute: [] }])
    : [{ resource: relevantAddress, attribute: ["arn"] }];
}

function makeAtomicBrokerFixture({ mode = "full-rls-application-canary", packageValue = packageChecksum, brokerActions = ["update"], includeBrokerChange = true, taskDefinitionAddress = taskDefinitionAddressForMode(mode), relevantAddress = taskDefinitionAddress, omitExecutorCollectionDependency = false, terraformConfiguration = terraformConfigurationSource, appendOnly = true, mutatePlan, mutateReader } = {}) {
  return makeFixture({
    packageValue,
    terraformConfiguration,
    appendOnly,
    mutatePlan: (plan) => {
      addBrokerAtomicPlanContract(plan, taskDefinitionAddress, relevantAddress, { omitExecutorCollectionDependency });
      if (includeBrokerChange) plan.resource_changes.push({
        address: "aws_lambda_function.broker",
        type: "aws_lambda_function",
        change: {
          actions: brokerActions,
          before: {
            filename: "/private/tmp/old-broker.zip",
            source_code_hash: "old-source-code-hash",
            environment: [{ variables: { BROKER_APPROVAL_EXPECTED_JSON: JSON.stringify({ packageChecksumSha256: packageValue }) } }],
          },
          after: {
            filename: packagePath,
            source_code_hash: packageSourceCodeHash,
            ...(JSON.stringify(brokerActions) === JSON.stringify(["create"])
              ? { environment: [{ variables: { BROKER_APPROVAL_EXPECTED_JSON: JSON.stringify({ packageChecksumSha256: packageChecksum }) } }] }
              : {}),
          },
          after_unknown: { environment: [{ variables: true }] },
        },
      });
      mutatePlan?.(plan);
    },
    mutateReader: (reader) => {
      const original = reader.getFunctionConfiguration;
      reader.getFunctionConfiguration = () => {
        const config = original();
        const variables = config.Environment.Variables;
        const taskDefinitions = JSON.parse(variables.BROKER_TASK_DEFINITIONS_JSON);
        for (const brokerMode of STAGE_B_MODES) taskDefinitions[brokerMode] = newArnFor(familyForMode(brokerMode));
        taskDefinitions[mode] = oldArnFor(familyForMode(mode));
        variables.BROKER_TASK_DEFINITIONS_JSON = JSON.stringify(taskDefinitions);
        return config;
      };
      mutateReader?.(reader);
    },
  });
}

function makeFreshImagePartialApplyReferenceFixture() {
  const fixture = makeAtomicBrokerFixture({ appendOnly: false });
  fixture.plan.resource_changes.filter((change) => change.type === "aws_ecs_task_definition" && !Object.hasOwn(change, "deposed")).forEach((change) => { change.change.actions = ["create", "delete"]; });
  const brokerFunction = fixture.plan.resource_changes.find((change) => change.address === "aws_lambda_function.broker");
  brokerFunction.change.after_unknown = { code_sha256: true, source_code_size: true, last_modified: true, qualified_arn: true, qualified_invoke_arn: true, version: true, environment: [{ variables: true }] };
  fixture.plan.resource_changes.push(
    { address: "aws_iam_policy.broker", mode: "managed", type: "aws_iam_policy", change: { actions: ["update"], before: { policy: "old" }, after: {}, after_unknown: { policy: true }, before_sensitive: {}, after_sensitive: {} } },
    { address: "aws_lambda_alias.reviewed", mode: "managed", type: "aws_lambda_alias", change: { actions: ["update"], before: { name: "reviewed", function_name: STAGE_B.brokerFunctionArn.split(":function:")[1], function_version: "2", routing_config: [] }, after: { name: "reviewed", function_name: STAGE_B.brokerFunctionArn.split(":function:")[1], routing_config: [] }, after_unknown: { function_version: true, routing_config: [] }, before_sensitive: { routing_config: [] }, after_sensitive: { routing_config: [] } } },
  );
  Object.entries(STAGE_B_TASK_DEFINITION_FAMILIES)
    .filter(([address]) => address !== backendAddress)
    .forEach(([address, family], index) => fixture.plan.resource_changes.push({
      address,
      deposed: `${String(index + 1).padStart(7, "0")}a`,
      mode: "managed",
      type: "aws_ecs_task_definition",
      change: {
        actions: ["delete"],
        before: { family, arn: oldArnFor(family).replace(":1", ":5"), skip_destroy: true },
        after: null,
      },
    }));
  fixture.planBytes = Buffer.from(JSON.stringify(fixture.plan));
  fixture.planJsonSha256 = sha256(fixture.planBytes);
  return fixture;
}

function makeBrokerLagRetryFixture(mode = "full-rls-admin-bootstrap") {
  const address = taskDefinitionAddressForMode(mode);
  const fixture = makeAtomicBrokerFixture({ mode, brokerActions: ["update"] });
  const change = fixture.plan.resource_changes.find((item) => item.address === address);
  const family = STAGE_B_TASK_DEFINITION_FAMILIES[address];
  const key = /\["([^"]+)"\]$/.exec(address)?.[1] || mode;
  const definitions = JSON.stringify([{ image: fixture.plan.variables[address.startsWith(executorCollectionAddress) ? "executor_image" : `${key}_image`].value, environment: [
    { name: "RELEASE_GIT_SHA", value: releaseSha },
    { name: "SOURCE_CONTRACT_SHA256", value: sourceContractSha256 },
    { name: "MIGRATION_SET_DIGEST", value: migrationSetDigest },
    { name: "PACKAGE_CHECKSUM_SHA256", value: packageChecksum },
  ] }]);
  const immutable = {
    family,
    network_mode: "awsvpc",
    requires_compatibilities: ["FARGATE"],
    cpu: "1024",
    memory: "2048",
    execution_role_arn: `arn:aws:iam::368992683803:role/${key}-execution`,
    task_role_arn: `arn:aws:iam::368992683803:role/${key}-task`,
    runtime_platform: { operating_system_family: "LINUX", cpu_architecture: "X86_64" },
    volume: [],
    ipc_mode: "",
    pid_mode: "",
    tags: { Environment: "production", ManagedBy: "Terraform", Component: "full-rls-green-stage-b" },
    container_definitions: definitions,
    arn: newArnFor(family),
  };
  change.change.actions = ["no-op"];
  change.change.before = { ...immutable };
  change.change.after = { ...immutable };
  const planned = fixture.plan.planned_values.root_module.resources.find((item) => item.address === address);
  planned.values = { ...immutable };
  fixture.planBytes = Buffer.from(JSON.stringify(fixture.plan));
  fixture.planJsonSha256 = sha256(fixture.planBytes);
  return fixture;
}

function makeInitialBrokerCreateFixture({ mutatePlan } = {}) {
  return makeAtomicBrokerFixture({
    brokerActions: ["create"],
    appendOnly: false,
    mutatePlan: (plan) => {
      for (const change of plan.resource_changes.filter((item) => item.type === "aws_ecs_task_definition")) {
        change.change.actions = ["create"];
        change.change.before = null;
        delete change.change.replace_paths;
      }
      mutatePlan?.(plan);
    },
  });
}

function withBrokerMapping(mapping) {
  return terraformConfigurationSource.replace(
    /  broker_task_definition_arns = merge\([\s\S]*?\n  \)/,
    `  broker_task_definition_arns = ${mapping}`,
  );
}

function withActiveBrokerMapping(expression) {
  return terraformConfigurationSource.replace(
    /^\s*active_broker_task_definition_arns\s*=\s*.+$/m,
    `  active_broker_task_definition_arns = ${expression}`,
  );
}

function makeMixedFixture({ mutatePlan, mutateReader } = {}) {
  return makeCreateOnlyFixture({
    mutatePlan: (plan) => {
      const change = plan.resource_changes.find((item) => item.address === backendAddress);
      change.change.actions = ["no-op"];
      const definition = JSON.stringify([{ image: plan.variables.backend_image.value, environment: [{ name: "RELEASE_GIT_SHA", value: plan.variables.image_release_sha.value }] }]);
      change.change.before = { family: change.change.before.family, arn: oldArnFor(change.change.before.family), container_definitions: definition };
      change.change.after = { family: change.change.after.family, arn: change.change.before.arn, container_definitions: definition };
      mutatePlan?.(plan);
    },
    mutateReader,
  });
}

test("exact 12-family allowlist passes and output is deterministic", () => {
  const fixture = makeFixture();
  const first = generate(fixture);
  const second = generate(fixture);
  assert.equal(first.oldTaskDefinitions.length, 12);
  assert.deepEqual([...first.oldTaskDefinitions.map((item) => item.family)].sort(), [...Object.values(STAGE_B_TASK_DEFINITION_FAMILIES)].sort());
  assert.deepEqual(first.oldTaskDefinitions.map((item) => item.classification), Array(12).fill("rollover"));
  assert.deepEqual(first, second);
});

test("unknown 13th family fails closed", () => {
  const fixture = makeFixture({ mutatePlan: (plan) => plan.resource_changes.push({
    address: 'aws_ecs_task_definition.other["unknown"]',
    type: "aws_ecs_task_definition",
    change: { actions: ["create"], after: { family: "mscqr-production-unknown" }, before: null },
  }) });
  assert.throws(() => generate(fixture), /unknown Stage B task-definition family/);
});

test("missing expected family fails closed", () => {
  const fixture = makeFixture({ mutatePlan: (plan) => {
    plan.resource_changes = plan.resource_changes.filter((item) => item.address !== readOnlyCanaryAddress);
  } });
  assert.throws(() => generate(fixture), /missing exact Stage B task-definition families/);
});

test("duplicate family fails closed", () => {
  const fixture = makeFixture({ mutatePlan: (plan) => plan.resource_changes.push(structuredClone(plan.resource_changes[0])) });
  assert.throws(() => generate(fixture), /duplicate current task-definition instance/);
});

test("fresh-image recovery partitions current runtime instances from reviewed deposed cleanups", () => {
  const audit = generate(makeFreshImagePartialApplyReferenceFixture());
  assert.equal(audit.currentTaskDefinitionReferenceCount, 12);
  assert.equal(audit.deposedTaskDefinitionCleanups.length, 11);
  assert.equal(audit.taskDefinitionMutationInstances.length, 23);
  assert.equal(new Set(audit.taskDefinitionMutationInstances.map((entry) => entry.mutationInstanceIdentity)).size, 23);
  assert.equal(audit.deposedTaskDefinitionCleanups.every((entry) => entry.classification === "PARTIAL_APPLY_RECOVERY_DEPOSED_TASK_DEFINITION_CLEANUP" && entry.remoteDeletion === false), true);
  assert.equal(audit.deposedTaskDefinitionCleanups.every((entry) => Object.values(entry.runtimeReferences).every((references) => references.length === 0)), true);
});

test("fresh-image approval re-derives the exact reference-audit mutation partition", () => {
  const fixture = makeFreshImagePartialApplyReferenceFixture();
  const audit = generate(fixture);
  assert.deepEqual(assertStageBFreshImageReferenceAuditBinding(fixture.plan, audit, { terraformConfiguration: fixture.options.terraformConfiguration, planJsonSha256: fixture.planJsonSha256 }), { currentCount: 12, deposedCount: 11, mutationInstanceCount: 23 });
  const rejects = [
    ["missing deposed cleanup", (candidate) => candidate.deposedTaskDefinitionCleanups.pop()],
    ["fake deposed cleanup", (candidate) => candidate.deposedTaskDefinitionCleanups.push({ ...candidate.deposedTaskDefinitionCleanups[0], deposed: "deadbeef", mutationInstanceIdentity: candidate.deposedTaskDefinitionCleanups[0].mutationInstanceIdentity.replace(/deposed:[a-f0-9]{8}/, "deposed:deadbeef") })],
    ["altered deposed identity", (candidate) => { candidate.deposedTaskDefinitionCleanups[0].deposed = "deadbeef"; }],
    ["duplicate deposed cleanup", (candidate) => candidate.deposedTaskDefinitionCleanups.push(structuredClone(candidate.deposedTaskDefinitionCleanups[0]))],
    ["missing mutation instance", (candidate) => candidate.taskDefinitionMutationInstances.pop()],
    ["fake mutation instance", (candidate) => candidate.taskDefinitionMutationInstances.push({ ...candidate.taskDefinitionMutationInstances[0], terraformAddress: "aws_ecs_task_definition.candidate[\"fake\"]" })],
    ["current converted to deposed", (candidate) => { candidate.taskDefinitionMutationInstances[0].classification = "PARTIAL_APPLY_RECOVERY_DEPOSED_TASK_DEFINITION_CLEANUP"; }],
    ["deposed converted to current", (candidate) => { candidate.taskDefinitionMutationInstances.find((entry) => entry.classification === "PARTIAL_APPLY_RECOVERY_DEPOSED_TASK_DEFINITION_CLEANUP").classification = "CURRENT_RUNTIME_TASK_DEFINITION"; }],
    ["mutation action changed", (candidate) => { candidate.deposedTaskDefinitionCleanups[0].actions = ["create"]; }],
    ["mutation classification changed", (candidate) => { candidate.deposedTaskDefinitionCleanups[0].classification = "CURRENT_RUNTIME_TASK_DEFINITION"; }],
    ["false no-live-reference claim", (candidate) => { candidate.services.push({ taskDefinition: candidate.deposedTaskDefinitionCleanups[0].beforeTaskDefinitionArn }); }],
    ["prohibited deposed live reference", (candidate) => { candidate.broker.liveTaskDefinitionMappings[0].taskDefinitionArn = candidate.deposedTaskDefinitionCleanups[0].beforeTaskDefinitionArn; }],
    ["correct counts wrong identities", (candidate) => { candidate.taskDefinitionMutationInstances[0].mutationInstanceIdentity = "wrong"; }],
    ["correct identities wrong classifications", (candidate) => { candidate.taskDefinitionMutationInstances.find((entry) => entry.classification === "CURRENT_RUNTIME_TASK_DEFINITION").classification = "wrong"; }],
    ["address-only equivalent identity", (candidate) => { candidate.deposedTaskDefinitionCleanups[0].terraformAddress = backendAddress; }],
  ];
  for (const [label, mutate] of rejects) {
    const candidate = structuredClone(audit);
    mutate(candidate);
    assert.throws(() => assertStageBFreshImageReferenceAuditBinding(fixture.plan, candidate, { terraformConfiguration: fixture.options.terraformConfiguration, planJsonSha256: fixture.planJsonSha256 }), undefined, label);
  }
});

test("fresh-image approval binds every current replacement to complete rollover evidence", () => {
  const fixture = makeFreshImagePartialApplyReferenceFixture();
  const audit = generate(fixture);
  assert.ok(audit.plannedAtomicBrokerRollovers.length > 0);
  const rolloverEntry = audit.oldTaskDefinitions.find((entry) => entry.brokerReferenceModes.length > 0);
  const rolloverMode = rolloverEntry.brokerReferenceModes[0];
  const rejects = [
    ["missing current rollover", (candidate) => candidate.oldTaskDefinitions.pop()],
    ["duplicate current rollover", (candidate) => candidate.oldTaskDefinitions.push(structuredClone(candidate.oldTaskDefinitions[0]))],
    ["wrong old task definition", (candidate) => { candidate.oldTaskDefinitions[0].oldTaskDefinitionArn = oldArnFor("wrong-family"); }],
    ["missing service reference field", (candidate) => { delete candidate.oldTaskDefinitions[0].serviceReferences; }],
    ["false service reference", (candidate) => { candidate.oldTaskDefinitions[0].serviceReferences = ["unexpected-service"]; }],
    ["missing live task reference field", (candidate) => { delete candidate.oldTaskDefinitions[0].runningTaskReferences; }],
    ["altered live task reference", (candidate) => { candidate.oldTaskDefinitions[0].runningTaskReferences = ["unexpected-task"]; }],
    ["top-level service reference contradiction", (candidate) => { candidate.services.push({ taskDefinition: rolloverEntry.oldTaskDefinitionArn, serviceName: "unexpected-service" }); }],
    ["top-level running reference contradiction", (candidate) => { candidate.runningTasks.push({ taskDefinitionArn: rolloverEntry.oldTaskDefinitionArn, taskArn: "unexpected-running-task" }); }],
    ["top-level pending reference contradiction", (candidate) => { candidate.pendingTasks.push({ taskDefinitionArn: rolloverEntry.oldTaskDefinitionArn, taskArn: "unexpected-pending-task" }); }],
    ["synchronized service predecessor reference", (candidate) => {
      const entry = candidate.oldTaskDefinitions.find((item) => item.terraformAddress === rolloverEntry.terraformAddress);
      candidate.services.push({ taskDefinition: rolloverEntry.oldTaskDefinitionArn, serviceName: "live-service" });
      entry.serviceReferences = ["live-service"];
    }],
    ["synchronized running predecessor reference", (candidate) => {
      const entry = candidate.oldTaskDefinitions.find((item) => item.terraformAddress === rolloverEntry.terraformAddress);
      candidate.runningTasks.push({ taskDefinitionArn: rolloverEntry.oldTaskDefinitionArn, taskArn: "live-running-task" });
      entry.runningTaskReferences = ["live-running-task"];
    }],
    ["synchronized pending predecessor reference", (candidate) => {
      const entry = candidate.oldTaskDefinitions.find((item) => item.terraformAddress === rolloverEntry.terraformAddress);
      candidate.pendingTasks.push({ taskDefinitionArn: rolloverEntry.oldTaskDefinitionArn, taskArn: "live-pending-task" });
      entry.pendingTaskReferences = ["live-pending-task"];
    }],
    ["synchronized transitional predecessor reference", (candidate) => {
      const entry = candidate.oldTaskDefinitions.find((item) => item.terraformAddress === rolloverEntry.terraformAddress);
      candidate.transitionalTasks.push({ taskDefinitionArn: rolloverEntry.oldTaskDefinitionArn, taskArn: "live-transitional-task", lastStatus: "ACTIVATING" });
      entry.transitionalTaskReferences = ["live-transitional-task"];
    }],
    ["entry service reference contradicts top level", (candidate) => { candidate.oldTaskDefinitions.find((entry) => entry.terraformAddress === rolloverEntry.terraformAddress).serviceReferences = ["unexpected-service"]; }],
    ["entry running reference contradicts top level", (candidate) => { candidate.oldTaskDefinitions.find((entry) => entry.terraformAddress === rolloverEntry.terraformAddress).runningTaskReferences = ["unexpected-running-task"]; }],
    ["entry pending reference contradicts top level", (candidate) => { candidate.oldTaskDefinitions.find((entry) => entry.terraformAddress === rolloverEntry.terraformAddress).pendingTaskReferences = ["unexpected-pending-task"]; }],
    ["ACTIVATING predecessor reference", (candidate) => { candidate.transitionalTasks.push({ taskDefinitionArn: rolloverEntry.oldTaskDefinitionArn, taskArn: "activating-task", lastStatus: "ACTIVATING" }); }],
    ["DEACTIVATING predecessor reference", (candidate) => { candidate.transitionalTasks.push({ taskDefinitionArn: rolloverEntry.oldTaskDefinitionArn, taskArn: "deactivating-task", lastStatus: "DEACTIVATING" }); }],
    ["STOPPING predecessor reference", (candidate) => { candidate.transitionalTasks.push({ taskDefinitionArn: rolloverEntry.oldTaskDefinitionArn, taskArn: "stopping-task", lastStatus: "STOPPING" }); }],
    ["canonical broker mode removed from entry", (candidate) => { candidate.oldTaskDefinitions.find((entry) => entry.terraformAddress === rolloverEntry.terraformAddress).brokerReferenceModes = []; }],
    ["canonical broker mode removed from proof", (candidate) => { candidate.plannedAtomicBrokerRollovers = candidate.plannedAtomicBrokerRollovers.filter((proof) => proof.mode !== rolloverMode); }],
    ["missing planned atomic rollover", (candidate) => { candidate.plannedAtomicBrokerRollovers.pop(); }],
    ["altered planned atomic rollover", (candidate) => { candidate.plannedAtomicBrokerRollovers[0].oldTaskDefinitionArn = oldArnFor("wrong-family"); }],
    ["broker mapping wrong predecessor", (candidate) => { candidate.broker.liveTaskDefinitionMappings.find((mapping) => mapping.mode === rolloverMode).taskDefinitionArn = oldArnFor("wrong-family"); }],
    ["broker mapping missing", (candidate) => { candidate.broker.liveTaskDefinitionMappings = candidate.broker.liveTaskDefinitionMappings.filter((mapping) => mapping.mode !== rolloverMode); }],
    ["broker mapping duplicate", (candidate) => { const mapping = candidate.broker.liveTaskDefinitionMappings.find((item) => item.mode === rolloverMode); candidate.broker.liveTaskDefinitionMappings.push(structuredClone(mapping)); }],
    ["broker mapping wrong mode", (candidate) => { candidate.broker.liveTaskDefinitionMappings.find((mapping) => mapping.mode === rolloverMode).mode = "wrong-mode"; }],
    ["extra mapping for another current predecessor", (candidate) => { candidate.broker.liveTaskDefinitionMappings.push({ mode: "unexpected-mode", taskDefinitionArn: audit.oldTaskDefinitions.find((entry) => entry.brokerReferenceModes.length === 0).oldTaskDefinitionArn }); }],
    ["swapped broker mode mappings", (candidate) => { const first = candidate.broker.liveTaskDefinitionMappings[0]; const second = candidate.broker.liveTaskDefinitionMappings[1]; [first.taskDefinitionArn, second.taskDefinitionArn] = [second.taskDefinitionArn, first.taskDefinitionArn]; }],
    ["swapped rollover evidence", (candidate) => {
      const first = candidate.oldTaskDefinitions[0];
      const second = candidate.oldTaskDefinitions[1];
      [first.oldTaskDefinitionArn, second.oldTaskDefinitionArn] = [second.oldTaskDefinitionArn, first.oldTaskDefinitionArn];
    }],
    ["mutation identity preserved but reference falsified", (candidate) => { candidate.oldTaskDefinitions[0].rollbackArn = oldArnFor("wrong-family"); }],
    ["correct counts with wrong rollover identity", (candidate) => { candidate.oldTaskDefinitions[0].terraformAddress = candidate.oldTaskDefinitions[1].terraformAddress; }],
    ["stale audit plan binding", (candidate) => { candidate.planJsonSha256 = "f".repeat(64); }],
  ];
  for (const [label, mutate] of rejects) {
    const candidate = structuredClone(audit);
    mutate(candidate);
    assert.throws(() => assertStageBFreshImageReferenceAuditBinding(fixture.plan, candidate, { terraformConfiguration: fixture.options.terraformConfiguration, planJsonSha256: fixture.planJsonSha256 }), undefined, label);
  }
});

test("fresh-image reference audit reaches the real plan approval validator", () => {
  const fixture = makeFreshImagePartialApplyReferenceFixture();
  const audit = generate(fixture);
  const auditBytes = Buffer.from(JSON.stringify(audit));
  assert.doesNotThrow(() => assertStageBPlan(fixture.plan, {
    freshImagePartialApplyRecovery: true,
    referenceAudit: audit,
    referenceAuditBytes: auditBytes,
    referenceAuditSha256: sha256(auditBytes),
    planJsonBytes: fixture.planBytes,
    planJsonSha256: fixture.planJsonSha256,
    terraformConfiguration: fixture.options.terraformConfiguration,
    trustedCallerArn: callerArn,
    now,
  }));
});

for (const [label, mutatePlan, expected] of [
  ["malformed deposed identity", (fixture) => { fixture.plan.resource_changes.find((change) => Object.hasOwn(change, "deposed")).deposed = "bad!"; }, /unexpected or malformed deposed/],
  ["duplicate deposed identity", (fixture) => { const cleanup = fixture.plan.resource_changes.find((change) => Object.hasOwn(change, "deposed")); fixture.plan.resource_changes.push(structuredClone(cleanup)); }, /duplicate deposed/],
  ["unexpected deposed instance", (fixture) => { const cleanup = fixture.plan.resource_changes.find((change) => Object.hasOwn(change, "deposed")); cleanup.address = 'aws_ecs_task_definition.candidate["unknown"]'; }, /unknown Stage B task-definition family or address|unexpected or malformed deposed/],
  ["current instance classified as deposed", (fixture) => { const current = fixture.plan.resource_changes.find((change) => change.address === backendAddress); current.deposed = "deadbeef"; }, /unexpected or malformed deposed/],
  ["duplicate current instance", (fixture) => { const current = fixture.plan.resource_changes.find((change) => change.address === backendAddress); fixture.plan.resource_changes.push(structuredClone(current)); }, /duplicate current task-definition instance/],
]) {
  test(`fresh-image reference partition rejects ${label}`, () => {
    const fixture = makeFreshImagePartialApplyReferenceFixture();
    mutatePlan(fixture);
    fixture.planBytes = Buffer.from(JSON.stringify(fixture.plan));
    fixture.planJsonSha256 = sha256(fixture.planBytes);
    assert.throws(() => generate(fixture), expected);
  });
}

test("fresh-image reference audit rejects a deposed task definition that remains runtime-referenced", () => {
  const fixture = makeFreshImagePartialApplyReferenceFixture();
  const deposed = fixture.plan.resource_changes.find((change) => Object.hasOwn(change, "deposed"));
  fixture.reader.listServices = () => [serviceArnFor(0)];
  fixture.reader.describeServices = () => ({ services: [serviceRecord(serviceArnFor(0), 0, deposed.change.before.arn)], failures: [] });
  const describeTaskDefinition = fixture.reader.describeTaskDefinition;
  fixture.reader.describeTaskDefinition = (reference) => {
    const response = describeTaskDefinition(reference);
    response.taskDefinition.taskDefinitionArn = reference;
    response.taskDefinition.revision = Number(reference.split(":").at(-1));
    return response;
  };
  assert.throws(() => generate(fixture), /Deposed task definition remains referenced/);
});

for (const [label, mutateReader, expected] of [
  ["service", (reader, oldArn) => { reader.listServices = () => ["arn:aws:ecs:eu-west-2:368992683803:service/mscqr-prod-euw2-main/stage-b"]; reader.describeServices = () => ({ services: [{ serviceArn: "arn:aws:ecs:eu-west-2:368992683803:service/mscqr-prod-euw2-main/stage-b", serviceName: "stage-b", taskDefinition: oldArn, runningCount: 0, pendingCount: 0, status: "ACTIVE" }], failures: [] }); }, /Superseded task definition remains referenced/],
  ["running task", (reader, oldArn) => { reader.listTasks = (status) => status === "RUNNING" ? ["arn:aws:ecs:eu-west-2:368992683803:task/mscqr-prod-euw2-main/run"] : []; reader.describeTasks = () => ({ tasks: [{ taskArn: "arn:aws:ecs:eu-west-2:368992683803:task/mscqr-prod-euw2-main/run", taskDefinitionArn: oldArn, lastStatus: "RUNNING", desiredStatus: "RUNNING", group: "service:stage-b" }], failures: [] }); }, /Superseded task definition remains referenced/],
  ["pending task", (reader, oldArn) => { reader.listTasks = () => ["arn:aws:ecs:eu-west-2:368992683803:task/mscqr-prod-euw2-main/pending"]; reader.describeTasks = () => ({ tasks: [{ taskArn: "arn:aws:ecs:eu-west-2:368992683803:task/mscqr-prod-euw2-main/pending", taskDefinitionArn: oldArn, lastStatus: "PENDING", desiredStatus: "RUNNING", group: "service:stage-b" }], failures: [] }); }, /Superseded task definition remains referenced/],
]) {
  test(`${label} reference to an old revision fails`, () => {
    const oldArn = oldArnFor(Object.values(STAGE_B_TASK_DEFINITION_FAMILIES)[0]);
    const fixture = makeFixture({ mutateReader: (reader) => mutateReader(reader, oldArn) });
    assert.throws(() => generate(fixture), expected);
  });
}

test("zero service, running-task, and pending-task references passes", () => {
  const audit = generate(makeFixture());
  assert.deepEqual(audit.services, []);
  assert.deepEqual(audit.runningTasks, []);
  assert.deepEqual(audit.pendingTasks, []);
  assert.equal(audit.allOldRevisionsUnreferenced, true);
});

test("allowlisted create-only family passes and is recorded explicitly", () => {
  const audit = generate(makeCreateOnlyFixture());
  assert.equal(audit.oldTaskDefinitions.length, 11);
  assert.deepEqual(audit.createOnlyTaskDefinitions, [{
    terraformAddress: readOnlyCanaryAddress,
    family: readOnlyCanaryFamily,
    proposedFamily: readOnlyCanaryFamily,
    classification: "create-only",
    priorTaskDefinitionArn: null,
    serviceReferences: [],
    runningTaskReferences: [],
    pendingTaskReferences: [],
    brokerReferenceModes: [],
  }]);
});

test("create-only family is not sent to DescribeTaskDefinition", () => {
  const fixture = makeCreateOnlyFixture();
  const calls = [];
  const original = fixture.reader.describeTaskDefinition;
  fixture.reader.describeTaskDefinition = (reference) => {
    calls.push(reference);
    return original(reference);
  };
  generate(fixture);
  assert.equal(calls.length, 11);
  assert.equal(calls.some((reference) => reference.includes(readOnlyCanaryFamily)), false);
});

test("create-only family with an unexpected prior ARN fails closed", () => {
  const fixture = makeCreateOnlyFixture({ mutatePlan: (plan) => {
    const change = plan.resource_changes.find((item) => item.address === readOnlyCanaryAddress);
    change.change.before = { family: readOnlyCanaryFamily, arn: oldArnFor(readOnlyCanaryFamily) };
  } });
  assert.throws(() => generate(fixture), /create-only task definition unexpectedly has a prior ARN/);
});

test("rollover family missing its prior ARN fails closed", () => {
  const fixture = makeFixture({ mutatePlan: (plan) => {
    const change = plan.resource_changes.find((item) => item.address !== readOnlyCanaryAddress);
    change.change.before = { family: change.change.before.family };
  } });
  assert.throws(() => generate(fixture), /rollover is missing its prior task-definition ARN/);
});

test("the 11 rollover live-reference checks remain enforced with a create-only family", () => {
  const rolloverFamily = Object.values(STAGE_B_TASK_DEFINITION_FAMILIES).find((family) => family !== readOnlyCanaryFamily);
  const fixture = makeCreateOnlyFixture({ mutateReader: (reader) => {
    reader.listServices = () => [serviceArnFor(0)];
    reader.describeServices = () => ({ services: [serviceRecord(serviceArnFor(0), 0, oldArnFor(rolloverFamily))], failures: [] });
  } });
  assert.throws(() => generate(fixture), /Superseded task definition remains referenced/);
});

test("create-only family live references fail closed", () => {
  const fixture = makeCreateOnlyFixture({ mutateReader: (reader) => {
    reader.listServices = () => [serviceArnFor(0)];
    reader.describeServices = () => ({ services: [serviceRecord(serviceArnFor(0), 0, newArnFor(readOnlyCanaryFamily))], failures: [] });
  } });
  assert.throws(() => generate(fixture), /Create-only task-definition family remains referenced/);
});

test("mixed rollover, create-only, and no-op plan classifications pass", () => {
  const audit = generate(makeMixedFixture());
  assert.equal(audit.oldTaskDefinitions.length, 10);
  assert.equal(audit.createOnlyTaskDefinitions.length, 1);
  assert.deepEqual(audit.noOpTaskDefinitions, [{
    terraformAddress: backendAddress,
    family: STAGE_B_TASK_DEFINITION_FAMILIES[backendAddress],
    proposedFamily: STAGE_B_TASK_DEFINITION_FAMILIES[backendAddress],
    classification: "no-op",
    priorTaskDefinitionArn: oldArnFor(STAGE_B_TASK_DEFINITION_FAMILIES[backendAddress]),
    serviceReferences: [],
    runningTaskReferences: [],
    pendingTaskReferences: [],
    brokerReferenceModes: [],
  }]);
});

test("append-only retry records twelve current create/no-op definitions", () => {
  const audit = generate(makeCreateOnlyFixture({
    appendOnly: true,
    mutatePlan: (plan) => {
      const change = plan.resource_changes.find((item) => item.address === backendAddress);
      const family = STAGE_B_TASK_DEFINITION_FAMILIES[backendAddress];
      const definitions = JSON.stringify([{ image: plan.variables.backend_image.value, environment: [
        { name: "RELEASE_GIT_SHA", value: releaseSha },
      ] }]);
      const immutable = {
        network_mode: "awsvpc",
        requires_compatibilities: ["FARGATE"],
        cpu: "1024",
        memory: "2048",
        execution_role_arn: "arn:aws:iam::368992683803:role/backend-execution",
        task_role_arn: "arn:aws:iam::368992683803:role/backend-task",
        runtime_platform: { operating_system_family: "LINUX", cpu_architecture: "X86_64" },
        volume: [],
        ipc_mode: "",
        pid_mode: "",
        tags: { Environment: "production", ManagedBy: "Terraform", Component: "full-rls-green-stage-b" },
      };
      change.change.actions = ["no-op"];
      change.change.before = { ...change.change.after, ...immutable, arn: newArnFor(family), container_definitions: definitions };
      change.change.after = { ...change.change.before };
      const planned = plan.planned_values.root_module.resources.find((item) => item.address === backendAddress);
      planned.values = { ...planned.values, ...change.change.after };
    },
  }));
  assert.deepEqual(audit.currentTaskDefinitions, { currentCreates: 11, currentNoOps: 1, total: 12 });
});

test("all retained revisions are valid live references, but an unrecorded revision fails", () => {
  const addSecondGeneration = (plan) => {
    for (const address of Object.keys(STAGE_B_TASK_DEFINITION_FAMILIES)) {
      const family = STAGE_B_TASK_DEFINITION_FAMILIES[address];
      let retained = plan.resource_changes.find((item) => item.address === retainedAddressFor(address));
      if (!retained) {
        retained = { address: retainedAddressFor(address), type: "aws_ecs_task_definition", change: { actions: ["no-op"], before: { family, arn: oldArnFor(family) }, after: { family } } };
        plan.resource_changes.push(retained);
      }
      const second = structuredClone(retained);
      second.address = retainedAddressFor(address, "bbbbbbbb");
      second.change.before.arn = second.change.before.arn.replace(":1", ":2");
      plan.resource_changes.push(second);
    }
  };
  const olderService = makeAtomicBrokerFixture({ mutatePlan: addSecondGeneration, mutateReader: (reader) => {
    reader.listServices = () => [serviceArnFor(0)];
    reader.describeServices = () => ({ services: [serviceRecord(serviceArnFor(0), 0, oldArnFor(STAGE_B_TASK_DEFINITION_FAMILIES[backendAddress]))], failures: [] });
  } });
  olderService.plan.relevant_attributes.push({ resource: executorCollectionAddress, attribute: [] });
  assert.doesNotThrow(() => generate(olderService));

  const unrecorded = makeAtomicBrokerFixture({ mutatePlan: addSecondGeneration, mutateReader: (reader) => {
    reader.listServices = () => [serviceArnFor(0)];
    reader.describeServices = () => ({ services: [serviceRecord(serviceArnFor(0), 0, `${oldArnFor(STAGE_B_TASK_DEFINITION_FAMILIES[backendAddress]).slice(0, -1)}99`)], failures: [] });
  } });
  unrecorded.plan.relevant_attributes.push({ resource: executorCollectionAddress, attribute: [] });
  assert.throws(() => generate(unrecorded), /ECS task-definition observation is incomplete|Superseded task definition remains referenced|Create-only task-definition family remains referenced/);
});

test("running and pending tasks may reference different retained generations", () => {
  const fixture = makeAtomicBrokerFixture({ mutatePlan: (plan) => {
    for (const address of Object.keys(STAGE_B_TASK_DEFINITION_FAMILIES)) {
      const family = STAGE_B_TASK_DEFINITION_FAMILIES[address];
      let retained = plan.resource_changes.find((item) => item.address === retainedAddressFor(address));
      if (!retained) {
        retained = { address: retainedAddressFor(address), type: "aws_ecs_task_definition", change: { actions: ["no-op"], before: { family, arn: oldArnFor(family) }, after: { family } } };
        plan.resource_changes.push(retained);
      }
      const second = structuredClone(retained);
      second.address = retainedAddressFor(address, "bbbbbbbb");
      second.change.before.arn = second.change.before.arn.replace(":1", ":2");
      plan.resource_changes.push(second);
    }
    plan.relevant_attributes.push({ resource: executorCollectionAddress, attribute: [] });
  }, mutateReader: (reader) => {
    reader.listTasks = () => [taskArnFor("RUNNING", 0), taskArnFor("PENDING", 0)];
    reader.describeTasks = (arns) => ({ tasks: arns.map((arn) => taskRecord(arn, arn.includes("running") ? "RUNNING" : "PENDING", arn.includes("running") ? oldArnFor(STAGE_B_TASK_DEFINITION_FAMILIES[backendAddress]) : newArnFor(STAGE_B_TASK_DEFINITION_FAMILIES[backendAddress]))), failures: [] });
  } });
  assert.doesNotThrow(() => generate(fixture));
});

test("revision-keyed retained history supports a second generation", () => {
  const fixture = makeAtomicBrokerFixture({
    appendOnly: true,
    mutatePlan: (plan) => {
      for (const address of Object.keys(STAGE_B_TASK_DEFINITION_FAMILIES)) {
        const retained = plan.resource_changes.find((item) => item.address === retainedAddressFor(address));
        const second = address === readOnlyCanaryAddress
          ? { address: retainedAddressFor(address, "0000001"), type: "aws_ecs_task_definition", change: { actions: ["no-op"], before: { family: readOnlyCanaryFamily, arn: oldArnFor(readOnlyCanaryFamily).replace(":1", ":2") }, after: { family: readOnlyCanaryFamily } } }
          : { ...structuredClone(retained), address: retained.address.replace("aaaaaaaa-", "0000001-") };
        if (address !== readOnlyCanaryAddress) second.change.before.arn = second.change.before.arn.replace(":1", ":2");
        plan.resource_changes.push(second);
      }
      plan.relevant_attributes.push({ resource: executorCollectionAddress, attribute: [] }, { resource: canaryAddress, attribute: ["arn"] });
    },
    mutateReader: (reader) => {
      const original = reader.getFunctionConfiguration;
      reader.getFunctionConfiguration = () => {
        const config = original();
        const variables = config.Environment.Variables;
        const taskDefinitions = JSON.parse(variables.BROKER_TASK_DEFINITIONS_JSON);
        for (const mode of STAGE_B_MODES) taskDefinitions[mode] = newArnFor(familyForMode(mode));
        variables.BROKER_TASK_DEFINITIONS_JSON = JSON.stringify(taskDefinitions);
        return config;
      };
    },
  });
  const audit = generate(fixture);
  assert.equal(audit.retainedTaskDefinitions.length, 23);
  assert.equal(audit.newestRetainedTaskDefinitions.length, 12);
  assert.equal(new Set(audit.retainedTaskDefinitions.map((entry) => entry.terraformAddress)).size, 23);
});

test("retained task definitions require ACTIVE status", () => {
  assert.doesNotThrow(() => generate(makeAtomicBrokerFixture()));
  for (const status of ["INACTIVE", "DELETE_IN_PROGRESS", undefined, "UNKNOWN"]) {
    const fixture = makeAtomicBrokerFixture({ mutateReader: (reader) => {
      const original = reader.describeTaskDefinition;
      reader.describeTaskDefinition = (reference) => {
        const response = original(reference);
        if (reference.includes("task-definition/")) response.taskDefinition.status = status;
        return response;
      };
    } });
    assert.throws(() => generate(fixture), new RegExp(`retained task definition.*family.*${status || "undefined"}`));
  }
});

test("multiple retained generations require every retained revision to be ACTIVE", () => {
  const addSecondGeneration = (plan) => {
    for (const address of Object.keys(STAGE_B_TASK_DEFINITION_FAMILIES)) {
      const retained = plan.resource_changes.find((item) => item.address === retainedAddressFor(address));
      const family = STAGE_B_TASK_DEFINITION_FAMILIES[address];
      const second = retained
        ? { ...structuredClone(retained), address: retainedAddressFor(address, "bbbbbbbb") }
        : { address: retainedAddressFor(address, "bbbbbbbb"), type: "aws_ecs_task_definition", change: { actions: ["no-op"], before: { family, arn: oldArnFor(family).replace(":1", ":2") }, after: { family } } };
      if (retained) second.change.before.arn = second.change.before.arn.replace(":1", ":2");
      plan.resource_changes.push(second);
    }
    plan.relevant_attributes.push({ resource: executorCollectionAddress, attribute: [] });
  };
  assert.doesNotThrow(() => generate(makeAtomicBrokerFixture({ mutatePlan: addSecondGeneration })));
  const inactive = makeAtomicBrokerFixture({ mutatePlan: addSecondGeneration, mutateReader: (reader) => {
    const original = reader.describeTaskDefinition;
    reader.describeTaskDefinition = (reference) => {
      const response = original(reference);
      if (reference.endsWith(":2")) response.taskDefinition.status = "INACTIVE";
      return response;
    };
  } });
  assert.throws(() => generate(inactive), /retained task definition.*family.*INACTIVE/);
});

test("newest retained revision is selected numerically, independent of generation-key ordering", () => {
  const fixture = makeAtomicBrokerFixture({
    mutatePlan: (plan) => {
      for (const address of Object.keys(STAGE_B_TASK_DEFINITION_FAMILIES)) {
        const retained = plan.resource_changes.find((item) => item.address === retainedAddressFor(address));
        const second = address === readOnlyCanaryAddress
          ? { address: retainedAddressFor(address, "0000001"), type: "aws_ecs_task_definition", change: { actions: ["no-op"], before: { family: readOnlyCanaryFamily, arn: oldArnFor(readOnlyCanaryFamily).replace(":1", ":2") }, after: { family: readOnlyCanaryFamily } } }
          : { ...structuredClone(retained), address: retained.address.replace("aaaaaaaa-", "0000001-"), change: { ...retained.change, before: { ...retained.change.before, arn: retained.change.before.arn.replace(":1", ":2") } } };
        plan.resource_changes.push(second);
      }
      plan.relevant_attributes.push({ resource: executorCollectionAddress, attribute: [] }, { resource: canaryAddress, attribute: ["arn"] });
    },
    mutateReader: (reader) => {
      const original = reader.getFunctionConfiguration;
      reader.getFunctionConfiguration = () => {
        const config = original();
        const variables = config.Environment.Variables;
        const taskDefinitions = JSON.parse(variables.BROKER_TASK_DEFINITIONS_JSON);
        taskDefinitions["full-rls-application-canary"] = newArnFor(familyForMode("full-rls-application-canary"));
        variables.BROKER_TASK_DEFINITIONS_JSON = JSON.stringify(taskDefinitions);
        return config;
      };
    },
  });
  const audit = generate(fixture);
  const retained = audit.retainedTaskDefinitions.find((entry) => entry.family === familyForMode("full-rls-application-canary") && entry.oldTaskDefinitionArn.endsWith(":2"));
  assert.equal(retained.brokerReferenceModes[0], "full-rls-application-canary");
  assert.equal(retained.brokerReferenceStatus, "planned-atomic-broker-rollover-v1");
});

test("older numeric revisions cannot satisfy the current rollover contract", () => {
  const fixture = makeAtomicBrokerFixture({
    mutatePlan: (plan) => {
      for (const address of Object.keys(STAGE_B_TASK_DEFINITION_FAMILIES)) {
        const retained = plan.resource_changes.find((item) => item.address === retainedAddressFor(address));
        const second = address === readOnlyCanaryAddress
          ? { address: retainedAddressFor(address, "ffffffff"), type: "aws_ecs_task_definition", change: { actions: ["no-op"], before: { family: readOnlyCanaryFamily, arn: oldArnFor(readOnlyCanaryFamily).replace(":1", ":2") }, after: { family: readOnlyCanaryFamily } } }
          : { ...structuredClone(retained), address: retained.address.replace("aaaaaaaa-", "ffffffff-"), change: { ...retained.change, before: { ...retained.change.before, arn: retained.change.before.arn.replace(":1", ":2") } } };
        plan.resource_changes.push(second);
      }
    },
    mutateReader: (reader) => {
      const original = reader.getFunctionConfiguration;
      reader.getFunctionConfiguration = () => {
        const config = original();
        const variables = config.Environment.Variables;
        const taskDefinitions = JSON.parse(variables.BROKER_TASK_DEFINITIONS_JSON);
        taskDefinitions["full-rls-application-canary"] = oldArnFor(familyForMode("full-rls-application-canary"));
        variables.BROKER_TASK_DEFINITIONS_JSON = JSON.stringify(taskDefinitions);
        return config;
      };
    },
  });
  assert.throws(() => generate(fixture), /superseded task definition|does not match the rollover before ARN/);
});

test("static retained family addresses fail closed", () => {
  const fixture = makeFixture({ appendOnly: true, mutatePlan: (plan) => {
    const retained = plan.resource_changes.find((item) => item.address === retainedAddressFor(backendAddress));
    retained.address = 'aws_ecs_task_definition.candidate_retained["backend"]';
  } });
  assert.throws(() => generate(fixture), /must be revision-keyed/);
});

test("malformed retained ARN revisions fail closed", () => {
  const fixture = makeFixture({ appendOnly: true, mutatePlan: (plan) => {
    const retained = plan.resource_changes.find((item) => item.address === retainedAddressFor(backendAddress));
    retained.change.before.arn = `${retained.change.before.arn.slice(0, -1)}x`;
  } });
  assert.throws(() => generate(fixture), /not a valid ECS task-definition ARN/);
});

test("duplicate retained family revisions fail closed", () => {
  const fixture = makeFixture({ appendOnly: true, mutatePlan: (plan) => {
    const retained = plan.resource_changes.find((item) => item.address === retainedAddressFor(backendAddress));
    plan.resource_changes.push({ ...structuredClone(retained), address: retained.address.replace("aaaaaaaa-", "bbbbbbbb-") });
  } });
  assert.throws(() => generate(fixture), /duplicate retained task-definition ARN|duplicate retained family and revision/);
});

test("current managed :5 and newest retained :4 are distinct valid identities", () => {
  assert.doesNotThrow(() => generate(makeCurrentRetainedPredecessorFixture()));
});

test("retained :4 cannot stand in for current managed :5", () => {
  const fixture = makeCurrentRetainedPredecessorFixture();
  const change = fixture.plan.resource_changes.find((item) => item.address === canaryAddress);
  change.change.before = { ...change.change.before, arn: oldArnFor(STAGE_B_TASK_DEFINITION_FAMILIES[canaryAddress]).replace(":1", ":4") };
  assert.throws(() => generate(fixture), /exact current managed task definition|also present in retained history/);
});

test("arbitrary :3 predecessor fails closed", () => {
  const fixture = makeCurrentRetainedPredecessorFixture();
  const change = fixture.plan.resource_changes.find((item) => item.address === canaryAddress);
  change.change.before = { ...change.change.before, arn: oldArnFor(STAGE_B_TASK_DEFINITION_FAMILIES[canaryAddress]).replace(":1", ":3") };
  assert.throws(() => generate(fixture), /exact current managed task definition/);
});

test("cross-family current predecessor fails closed", () => {
  assert.throws(() => generate(makeCurrentRetainedPredecessorFixture({ mutatePlan: (plan) => {
    const canary = plan.resource_changes.find((item) => item.address === canaryAddress);
    canary.change.before.arn = oldArnFor(STAGE_B_TASK_DEFINITION_FAMILIES[backendAddress]);
  } })), /exact current managed task definition|family/);
});

test("retained-history family corruption remains rejected", () => {
  assert.throws(() => generate(makeCurrentRetainedPredecessorFixture({ mutatePlan: (plan) => {
    const retained = plan.resource_changes.find((item) => item.address === retainedAddressFor(canaryAddress, "bbbbbbbb"));
    retained.change.before.arn = oldArnFor(STAGE_B_TASK_DEFINITION_FAMILIES[backendAddress]).replace(":1", ":4");
  } })), /retained task definition|family/);
});

test("current managed :5 and newest retained :4 pass full reference binding", () => {
  const fixture = makeAppendOnlyCurrentPredecessorFixture();
  validateBrokerPlan(fixture, generate(fixture));
});

for (const status of ["ACTIVATING", "DEACTIVATING", "STOPPING"]) {
  test(`transitional ${status} task cannot reference current rollover predecessor`, () => {
    const fixture = makeAppendOnlyCurrentPredecessorFixture();
    const audit = generate(fixture);
    const task = taskRecord(
      taskArnFor(status, 0),
      status,
      oldArnFor(STAGE_B_TASK_DEFINITION_FAMILIES[canaryAddress]).replace(":1", ":5"),
    );
    task.stageBScoped = true;
    audit.transitionalTasks.push(task);
    assert.throws(() => validateBrokerPlan(fixture, audit), /transitional task contains an unrecorded task-definition ARN/);
  });
}

for (const [name, observation] of [
  ["service", { serviceName: "stage-b-current", taskDefinition: oldArnFor(STAGE_B_TASK_DEFINITION_FAMILIES[canaryAddress]).replace(":1", ":5"), stageBScoped: true }],
  ["RUNNING task", { taskArn: "arn:aws:ecs:eu-west-2:368992683803:task/mscqr-prod-euw2-main/running-1", taskDefinitionArn: oldArnFor(STAGE_B_TASK_DEFINITION_FAMILIES[canaryAddress]).replace(":1", ":5"), lastStatus: "RUNNING", desiredStatus: "RUNNING", group: "service:stage-b", stageBScoped: true }],
  ["PENDING task", { taskArn: "arn:aws:ecs:eu-west-2:368992683803:task/mscqr-prod-euw2-main/pending-1", taskDefinitionArn: oldArnFor(STAGE_B_TASK_DEFINITION_FAMILIES[canaryAddress]).replace(":1", ":5"), lastStatus: "PENDING", desiredStatus: "RUNNING", group: "service:stage-b", stageBScoped: true }],
]) {
  test(`${name} cannot reference current rollover predecessor`, () => {
    const fixture = makeAppendOnlyCurrentPredecessorFixture();
    const audit = generate(fixture);
    audit[`${name === "service" ? "services" : name === "RUNNING task" ? "runningTasks" : "pendingTasks"}`].push(observation);
    assert.throws(() => validateBrokerPlan(fixture, audit), new RegExp(`${name} contains an unrecorded task-definition ARN`));
  });
}

test("no-op with a valid prior ARN passes", () => {
  assert.doesNotThrow(() => generate(makeMixedFixture()));
});

test("no-op without a prior ARN fails closed", () => {
  const fixture = makeMixedFixture({ mutatePlan: (plan) => {
    const change = plan.resource_changes.find((item) => item.address === backendAddress);
    change.change.before = { family: change.change.before.family };
  } });
  assert.throws(() => generate(fixture), /no-op task definition is missing its prior ARN/);
});

test("no-op family mismatch fails closed", () => {
  const fixture = makeMixedFixture({ mutatePlan: (plan) => {
    const change = plan.resource_changes.find((item) => item.address === backendAddress);
    change.change.before.family = readOnlyCanaryFamily;
  } });
  assert.throws(() => generate(fixture), /no-op task-definition family mismatch/);
});

test("batching is stable, non-mutating, bounded, and empty-safe", () => {
  const input = [1, 2, 3, 4, 5];
  assert.deepEqual(batch(input, 2), [[1, 2], [3, 4], [5]]);
  assert.deepEqual(input, [1, 2, 3, 4, 5]);
  assert.deepEqual(batch([], 10), []);
  assert.throws(() => batch(input, 0), /positive integer/);
  assert.throws(() => batch(input, 1.5), /positive integer/);
});

test("generator enforces current, maximum-age, and future-skew timestamps", () => {
  const fixture = makeFixture();
  assert.doesNotThrow(() => generate(fixture, { auditedAt: new Date(now.getTime() - STAGE_B_REFERENCE_AUDIT_MAX_AGE_MS + 1).toISOString() }));
  assert.throws(() => generate(fixture, { auditedAt: new Date(now.getTime() - STAGE_B_REFERENCE_AUDIT_MAX_AGE_MS).toISOString() }), /expired/);
  assert.doesNotThrow(() => generate(fixture, { auditedAt: new Date(now.getTime() + STAGE_B_REFERENCE_AUDIT_CLOCK_SKEW_MS).toISOString() }));
  assert.throws(() => generate(fixture, { auditedAt: new Date(now.getTime() - STAGE_B_REFERENCE_AUDIT_MAX_AGE_MS - 1).toISOString() }), /expired/);
  assert.throws(() => generate(fixture, { auditedAt: new Date(now.getTime() + STAGE_B_REFERENCE_AUDIT_CLOCK_SKEW_MS + 1).toISOString() }), /future/);
  assert.throws(() => generate(fixture, { auditedAt: "not-a-timestamp" }), /malformed/);
  const staleCliValue = parseCli([
    "--plan-json", "/tmp/plan.json", "--plan-sha256", planSha256, "--output", "/tmp/audit.json",
    "--region", "eu-west-2", "--cluster-arn", clusterArn,
    "--expected-package-checksum-sha256", packageChecksum, "--audited-at", "2026-07-31T13:00:00.000Z",
  ]).auditedAt;
  assert.throws(() => generate(fixture, { auditedAt: staleCliValue }), /expired/);
});

test("Stage B broker alias identity has one canonical qualified source", () => {
  assert.equal(assertStageBBrokerAliasArn(STAGE_B.brokerAliasArn), STAGE_B.brokerAliasArn);
  assert.throws(() => assertStageBBrokerAliasArn(STAGE_B.brokerFunctionArn), /Difference: alias, qualifier/);
  assert.throws(() => assertStageBBrokerAliasArn(STAGE_B.brokerAliasArn.replace(/function:[^:]+/, "function:other")), /Difference: function/);
  assert.throws(() => assertStageBBrokerAliasArn(STAGE_B.brokerAliasArn.replace(STAGE_B.region, "us-east-1")), /Difference: region/);
  assert.throws(() => assertStageBBrokerAliasArn(STAGE_B.brokerAliasArn.replace(STAGE_B.account, "000000000000")), /Difference: account/);
  assert.throws(() => assertStageBBrokerAliasArn(STAGE_B.brokerAliasArn.replace(/:[^:]+$/, ":v2")), /Difference: alias, qualifier/);
});

test("broker configuration identity accepts base, matching numeric, and resolved reviewed-alias forms", () => {
  const alias = { AliasArn: STAGE_B.brokerAliasArn, Name: STAGE_B.brokerAliasQualifier, FunctionVersion: "2" };
  for (const FunctionArn of [STAGE_B.brokerFunctionArn, `${STAGE_B.brokerFunctionArn}:2`, STAGE_B.brokerAliasArn]) {
    const identity = assertStageBBrokerConfigurationIdentity({ configuration: { FunctionArn, Version: "2" }, alias });
    assert.equal(identity.aliasArn, STAGE_B.brokerAliasArn);
    assert.equal(identity.resolvedVersionArn, `${STAGE_B.brokerFunctionArn}:2`);
  }
  assert.doesNotThrow(() => assertStageBBrokerConfigurationIdentity({
    configuration: { FunctionArn: `${STAGE_B.brokerFunctionArn}:15`, Version: "15" },
    alias: { ...alias, FunctionVersion: "15" },
  }));
  assert.doesNotThrow(() => generate(makeFixture({ mutateReader: (reader) => {
    const original = reader.getFunctionConfiguration;
    reader.getFunctionConfiguration = () => ({ ...original(), FunctionArn: STAGE_B.brokerAliasArn, Version: "2" });
    reader.getAlias = () => ({ ...alias });
  }})));
});

test("broker configuration identity rejects missing or inconsistent alias evidence", () => {
  const configuration = { FunctionArn: STAGE_B.brokerAliasArn, Version: "2" };
  const validAlias = { AliasArn: STAGE_B.brokerAliasArn, Name: STAGE_B.brokerAliasQualifier, FunctionVersion: "2" };
  assert.throws(() => assertStageBBrokerConfigurationIdentity({ configuration, alias: undefined }), /alias evidence/);
  assert.throws(() => assertStageBBrokerConfigurationIdentity({ configuration, alias: { ...validAlias, FunctionVersion: "3" } }), /version/);
  assert.throws(() => assertStageBBrokerConfigurationIdentity({ configuration, alias: { ...validAlias, AliasArn: `${STAGE_B.brokerFunctionArn}:live` } }), /identity/);
  assert.throws(() => assertStageBBrokerConfigurationIdentity({ configuration, alias: { ...validAlias, Name: "live" } }), /alias name/);
  assert.throws(() => assertStageBBrokerConfigurationIdentity({ configuration, alias: { ...validAlias, FunctionVersion: "$LATEST" } }), /version/);
  assert.throws(() => assertStageBBrokerConfigurationIdentity({ configuration: { ...configuration, Version: "foo" }, alias: validAlias }), /malformed/);
  assert.throws(() => assertStageBBrokerConfigurationIdentity({ configuration: { ...configuration, FunctionArn: `${STAGE_B.brokerFunctionArn}:3` }, alias: validAlias }), /outside/);
  for (const FunctionArn of [
    `${STAGE_B.brokerFunctionArn}:live`,
    `${STAGE_B.brokerFunctionArn}:foo`,
    `${STAGE_B.brokerFunctionArn}:`,
    `${STAGE_B.brokerFunctionArn}:$LATEST`,
    STAGE_B.brokerAliasArn.replace(/:reviewed$/, ":live"),
    STAGE_B.brokerFunctionArn.replace(STAGE_B.account, "000000000000"),
    STAGE_B.brokerFunctionArn.replace(STAGE_B.region, "us-east-1"),
    STAGE_B.brokerFunctionArn.replace(/broker$/, "other"),
  ]) assert.throws(() => assertStageBBrokerConfigurationIdentity({ configuration: { FunctionArn, Version: "2" }, alias: validAlias }), /outside/);
});

test("reference audit records base, alias, configuration, and resolved broker identities separately", () => {
  const fixture = makeFixture({ mutateReader: (reader) => {
    const original = reader.getFunctionConfiguration;
    reader.getFunctionConfiguration = () => ({ ...original(), FunctionArn: STAGE_B.brokerAliasArn, Version: "2" });
    reader.getAlias = () => ({ AliasArn: STAGE_B.brokerAliasArn, Name: STAGE_B.brokerAliasQualifier, FunctionVersion: "2" });
  }});
  const audit = generate(fixture);
  assert.deepEqual({
    functionArn: audit.broker.functionArn,
    aliasArn: audit.broker.aliasArn,
    aliasName: audit.broker.aliasName,
    aliasFunctionVersion: audit.broker.aliasFunctionVersion,
    configurationFunctionArn: audit.broker.configurationFunctionArn,
    configurationVersion: audit.broker.configurationVersion,
    resolvedVersionArn: audit.broker.resolvedVersionArn,
  }, {
    functionArn: STAGE_B.brokerFunctionArn,
    aliasArn: STAGE_B.brokerAliasArn,
    aliasName: STAGE_B.brokerAliasQualifier,
    aliasFunctionVersion: "2",
    configurationFunctionArn: STAGE_B.brokerAliasArn,
    configurationVersion: "2",
    resolvedVersionArn: `${STAGE_B.brokerFunctionArn}:2`,
  });
});

test("audit CLI derives the canonical broker alias and rejects broker overrides", () => {
  const base = ["--plan-json", "/tmp/plan.json", "--plan-sha256", planSha256, "--output", "/tmp/audit.json", "--region", "eu-west-2", "--cluster-arn", clusterArn, "--expected-package-checksum-sha256", packageChecksum];
  assert.equal(parseCli(base).brokerAliasArn, STAGE_B.brokerAliasArn);
  assert.throws(() => parseCli([...base, "--broker-function", STAGE_B.brokerAliasArn]), /not accepted; Stage B broker identity is canonical/);
});

test("Stage B broker Lambda identities have one executable source", () => {
  const canonicalPath = path.resolve("scripts/aws/production-green-stage-b-contract.mjs");
  const sourceFiles = [];
  const visit = (directory) => {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      const entryPath = path.join(directory, entry.name);
      if (entry.isDirectory()) visit(entryPath);
      else if (entry.name.endsWith(".mjs") && path.resolve(entryPath) !== canonicalPath) sourceFiles.push(entryPath);
    }
  };
  visit(path.resolve("scripts"));
  const duplicateLiterals = sourceFiles.flatMap((file) => {
    const source = fs.readFileSync(file, "utf8");
    return [STAGE_B.brokerAliasArn, STAGE_B.brokerFunctionArn, STAGE_B.brokerFunctionArnWildcard]
      .filter((literal) => source.includes(literal))
      .map((literal) => `${file}:${literal}`);
  });
  assert.deepEqual(duplicateLiterals, []);
});

const serviceArnFor = (index) => `arn:aws:ecs:eu-west-2:368992683803:service/mscqr-prod-euw2-main/stage-b-${index}`;
const taskArnFor = (status, index) => `arn:aws:ecs:eu-west-2:368992683803:task/mscqr-prod-euw2-main/${status.toLowerCase()}-${index}`;
const currentTaskDefinition = newArnFor(Object.values(STAGE_B_TASK_DEFINITION_FAMILIES)[0]);
const serviceRecord = (arn, index, taskDefinition = currentTaskDefinition) => ({ serviceArn: arn, serviceName: `stage-b-${index}`, taskDefinition, runningCount: 0, pendingCount: 0, status: "ACTIVE" });
const taskRecord = (arn, status, taskDefinitionArn = currentTaskDefinition) => ({ taskArn: arn, taskDefinitionArn, lastStatus: status, desiredStatus: "RUNNING", group: "service:stage-b" });

test("DescribeServices uses batches of at most 10 and accepts an exact complete multi-batch response", () => {
  const fixture = makeFixture();
  const listed = Array.from({ length: 25 }, (_, index) => serviceArnFor(index));
  const calls = [];
  fixture.reader.listServices = () => listed;
  fixture.reader.describeServices = (arns) => {
    calls.push([...arns]);
    return { services: arns.map((arn, index) => serviceRecord(arn, listed.indexOf(arn) + index)), failures: [] };
  };
  const audit = generate(fixture);
  assert.deepEqual(calls.map((items) => items.length), [10, 10, 5]);
  assert.equal(audit.services.length, 25);
});

test("empty service list makes no DescribeServices call", () => {
  const fixture = makeFixture();
  fixture.reader.describeServices = () => { throw new Error("must not be called"); };
  assert.doesNotThrow(() => generate(fixture));
});

for (const [name, response, expected] of [
  ["partial", { services: [serviceRecord(serviceArnFor(0), 0)], failures: [] }, /incomplete/],
  ["non-empty failures", { services: [], failures: [{ arn: serviceArnFor(0), reason: "MISSING" }] }, /contains failures/],
  ["malformed failures", { services: [], failures: [{}] }, /malformed failure/],
  ["duplicate", { services: [serviceRecord(serviceArnFor(0), 0), serviceRecord(serviceArnFor(0), 0)], failures: [] }, /duplicate service/],
  ["unexpected", { services: [serviceRecord(serviceArnFor(9), 9)], failures: [] }, /unexpected service/],
  ["missing required data", { services: [{ serviceArn: serviceArnFor(0), serviceName: "stage-b-0" }], failures: [] }, /incomplete/],
]) {
  test(`DescribeServices rejects ${name} responses`, () => {
    const fixture = makeFixture();
    fixture.reader.listServices = () => name === "partial" ? [serviceArnFor(0), serviceArnFor(1)] : [serviceArnFor(0)];
    fixture.reader.describeServices = () => response;
    assert.throws(() => generate(fixture), expected);
  });
}

test("DescribeTasks uses batches of at most 100 for the active desired-RUNNING task set", () => {
  const fixture = makeFixture();
  const listed = [
    ...Array.from({ length: 101 }, (_, index) => taskArnFor("RUNNING", index)),
    ...Array.from({ length: 101 }, (_, index) => taskArnFor("PENDING", index)),
  ];
  const calls = [];
  fixture.reader.listTasks = () => listed;
  fixture.reader.describeTasks = (arns) => {
    calls.push([...arns]);
    return { tasks: arns.map((arn) => taskRecord(arn, arn.includes("running") ? "RUNNING" : "PENDING")), failures: [] };
  };
  const audit = generate(fixture);
  assert.deepEqual(calls.map((items) => items.length), [100, 100, 2]);
  assert.equal(audit.runningTasks.length, 101);
  assert.equal(audit.pendingTasks.length, 101);
});

test("empty task lists make no DescribeTasks calls", () => {
  const fixture = makeFixture();
  fixture.reader.describeTasks = () => { throw new Error("must not be called"); };
  assert.doesNotThrow(() => generate(fixture));
});

for (const [name, response, expected] of [
  ["partial", { tasks: [], failures: [] }, /incomplete/],
  ["non-empty failures", { tasks: [], failures: [{ arn: taskArnFor("RUNNING", 0), reason: "MISSING" }] }, /contains failures/],
  ["malformed failures", { tasks: [], failures: [{}] }, /malformed failure/],
  ["duplicate", { tasks: [taskRecord(taskArnFor("RUNNING", 0), "RUNNING"), taskRecord(taskArnFor("RUNNING", 0), "RUNNING")], failures: [] }, /duplicate task/],
  ["unexpected", { tasks: [taskRecord(taskArnFor("RUNNING", 1), "RUNNING")], failures: [] }, /unexpected task/],
  ["malformed task-definition reference", { tasks: [taskRecord(taskArnFor("RUNNING", 0), "RUNNING", "not-an-arn")], failures: [] }, /invalid task-definition ARN/],
]) {
  test(`DescribeTasks rejects ${name} responses`, () => {
    const fixture = makeFixture();
    fixture.reader.listTasks = (status) => status === "RUNNING" ? [taskArnFor("RUNNING", 0)] : [];
    fixture.reader.describeTasks = () => response;
    assert.throws(() => generate(fixture), expected);
  });
}

test("missing and stale plan SHA values fail closed", () => {
  const fixture = makeFixture();
  assert.throws(() => generate(fixture, { planJsonSha256: "" }), /missing or malformed/);
  assert.throws(() => generate(fixture, { planJsonSha256: "0".repeat(64) }), /does not match/);
});

test("broker package checksum mismatch fails closed", () => {
  const fixture = makeFixture({ packageValue: "c".repeat(64) });
  assert.throws(() => generate(fixture), /Stale broker release checksum requires a planned broker update/);
});

test("valid atomic broker package checksum transition passes and is recorded", () => {
  const staleChecksum = "c".repeat(64);
  const fixture = makeAtomicBrokerFixture({ packageValue: staleChecksum });
  const audit = generate(fixture);
  assert.equal(audit.broker.releasePackageChecksumSha256, staleChecksum);
  assert.notEqual(audit.broker.brokerZipFileSha256, audit.broker.plannedReleasePackageChecksumSha256);
  assert.deepEqual(audit.plannedAtomicPackageChecksumTransition, {
    brokerTerraformAddress: "aws_lambda_function.broker",
    brokerEnvironmentReference: "local.broker_approval_expected",
    packageInputReference: "var.package_checksum_sha256",
    packagePath,
    liveReleasePackageChecksumSha256: staleChecksum,
    planBeforeReleasePackageChecksumSha256: staleChecksum,
    plannedReleasePackageChecksumSha256: packageChecksum,
    brokerZipFileSha256,
    plannedBrokerSourceCodeHashBase64: packageSourceCodeHash,
    planJsonSha256: fixture.planJsonSha256,
    transition: "plannedAtomicPackageChecksumTransition",
  });
  const auditBytes = Buffer.from(JSON.stringify(audit));
  assert.doesNotThrow(() => assertStageBPlan(fixture.plan, {
    referenceAudit: audit,
    referenceAuditBytes: auditBytes,
    referenceAuditSha256: sha256(auditBytes),
    planJsonBytes: fixture.planBytes,
    planJsonSha256: fixture.planJsonSha256,
    terraformConfiguration: fixture.options.terraformConfiguration,
    trustedCallerArn: callerArn,
    now,
  }));
});

test("live checksum already matching the planned checksum passes without a transition", () => {
  const audit = generate(makeAtomicBrokerFixture());
  assert.equal(audit.plannedAtomicPackageChecksumTransition, null);
});

test("broker no-op with a stale checksum fails closed", () => {
  assert.throws(
    () => generate(makeAtomicBrokerFixture({ packageValue: "c".repeat(64), brokerActions: ["no-op"] })),
    /broker actions/,
  );
});

test("broker update with the wrong planned checksum fails closed", () => {
  assert.throws(
    () => generate(makeAtomicBrokerFixture({
      packageValue: "c".repeat(64),
      mutatePlan: (plan) => { plan.variables.package_checksum_sha256.value = "d".repeat(64); },
    })),
    /checksum does not match the exact plan input|package bytes|source_code_hash/,
  );
});

test("broker update with a missing planned checksum fails closed", () => {
  assert.throws(
    () => generate(makeAtomicBrokerFixture({
      packageValue: "c".repeat(64),
      mutatePlan: (plan) => { delete plan.variables.package_checksum_sha256; },
    })),
    /checksum is missing or malformed|exact plan input/,
  );
});

test("broker update with the wrong source_code_hash fails closed", () => {
  assert.throws(
    () => generate(makeAtomicBrokerFixture({
      packageValue: "c".repeat(64),
      mutatePlan: (plan) => {
        plan.resource_changes.find((item) => item.address === "aws_lambda_function.broker").change.after.source_code_hash = "wrong";
      },
    })),
    /source_code_hash/,
  );
});

test("broker update with package bytes that do not match the checksum fails closed", () => {
  assert.throws(
    () => generate(makeAtomicBrokerFixture({
      packageValue: "c".repeat(64),
      mutatePlan: (plan) => { plan.variables.package_checksum_sha256.value = "d".repeat(64); },
    })),
    /package bytes|checksum does not match/,
  );
});

test("live checksum not matching the plan before-value fails closed", () => {
  assert.throws(
    () => generate(makeAtomicBrokerFixture({
      packageValue: "c".repeat(64),
      mutatePlan: (plan) => {
        const broker = plan.resource_changes.find((item) => item.address === "aws_lambda_function.broker");
        broker.change.before.environment[0].variables.BROKER_APPROVAL_EXPECTED_JSON = JSON.stringify({ packageChecksumSha256: "d".repeat(64) });
      },
    })),
    /before-value/,
  );
});

test("missing broker approval local reference fails closed", () => {
  assert.throws(
    () => generate(makeAtomicBrokerFixture({
      packageValue: "c".repeat(64),
      mutatePlan: (plan) => {
        plan.configuration.root_module.resources[0].expressions.environment[0].variables.references = [STAGE_B_BROKER_TASK_DEFINITION_REFERENCE];
      },
    })),
    /approval local reference/,
  );
});

test("provider-unknown broker environment after-value passes only with the full plan proof", () => {
  const fixture = makeAtomicBrokerFixture({ packageValue: "c".repeat(64) });
  assert.deepEqual(fixture.plan.resource_changes.find((item) => item.address === "aws_lambda_function.broker").change.after_unknown, { environment: [{ variables: true }] });
  assert.doesNotThrow(() => generate(fixture));
});

test("atomic package transition plan SHA binding remains enforced", () => {
  const fixture = makeAtomicBrokerFixture({ packageValue: "c".repeat(64) });
  const audit = generate(fixture);
  audit.plannedAtomicPackageChecksumTransition.planJsonSha256 = "0".repeat(64);
  const auditBytes = Buffer.from(JSON.stringify(audit));
  assert.throws(() => assertStageBPlan(fixture.plan, {
    referenceAudit: audit,
    referenceAuditBytes: auditBytes,
    referenceAuditSha256: sha256(auditBytes),
    planJsonBytes: fixture.planBytes,
    planJsonSha256: fixture.planJsonSha256,
    terraformConfiguration: fixture.options.terraformConfiguration,
    trustedCallerArn: callerArn,
    now,
  }), /planJsonSha256 does not match broker evidence/);
});

test("broker update without a reference audit fails closed", () => {
  const fixture = makeAtomicBrokerFixture();
  assert.throws(() => assertStageBPlan(fixture.plan, {
    planJsonBytes: fixture.planBytes,
    planJsonSha256: fixture.planJsonSha256,
    terraformConfiguration: fixture.options.terraformConfiguration,
    trustedCallerArn: callerArn,
    now,
  }), /explicit plan-bound reference audit/);
});

test("broker update with audit missing broker evidence fails closed", () => {
  const fixture = makeAtomicBrokerFixture();
  const audit = generate(fixture);
  delete audit.broker;
  assert.throws(() => assertStageBPlan(fixture.plan, {
    referenceAudit: audit,
    referenceAuditBytes: Buffer.from(JSON.stringify(audit)),
    referenceAuditSha256: sha256(Buffer.from(JSON.stringify(audit))),
    planJsonBytes: fixture.planBytes,
    planJsonSha256: fixture.planJsonSha256,
    terraformConfiguration: fixture.options.terraformConfiguration,
    trustedCallerArn: callerArn,
    now,
  }), /broker update reference audit evidence is missing/);
});

test("broker update with stale audit fails closed", () => {
  const fixture = makeAtomicBrokerFixture();
  const audit = generate(fixture);
  audit.auditedAt = "2026-07-31T13:00:00.000Z";
  assert.throws(() => assertStageBPlan(fixture.plan, {
    referenceAudit: audit,
    referenceAuditBytes: Buffer.from(JSON.stringify(audit)),
    referenceAuditSha256: sha256(Buffer.from(JSON.stringify(audit))),
    planJsonBytes: fixture.planBytes,
    planJsonSha256: fixture.planJsonSha256,
    terraformConfiguration: fixture.options.terraformConfiguration,
    trustedCallerArn: callerArn,
    now,
  }), /expired/);
});

test("broker update with wrong audit plan binding fails closed", () => {
  const fixture = makeAtomicBrokerFixture();
  const audit = generate(fixture);
  audit.planJsonSha256 = "0".repeat(64);
  assert.throws(() => assertStageBPlan(fixture.plan, {
    referenceAudit: audit,
    referenceAuditBytes: Buffer.from(JSON.stringify(audit)),
    referenceAuditSha256: sha256(Buffer.from(JSON.stringify(audit))),
    planJsonBytes: fixture.planBytes,
    planJsonSha256: fixture.planJsonSha256,
    terraformConfiguration: fixture.options.terraformConfiguration,
    now,
  }), /bound to a different plan JSON/);
});

test("complete broker update audit evidence passes", () => {
  const fixture = makeAtomicBrokerFixture();
  validateBrokerPlan(fixture, generate(fixture));
});

test("append-only audit without trusted caller attestation fails closed", () => {
  const fixture = makeAtomicBrokerFixture();
  const audit = generate(fixture);
  const auditBytes = Buffer.from(JSON.stringify(audit));
  assert.throws(() => assertStageBPlan(fixture.plan, {
    referenceAudit: audit,
    referenceAuditBytes: auditBytes,
    referenceAuditSha256: sha256(auditBytes),
    planJsonBytes: fixture.planBytes,
    planJsonSha256: fixture.planJsonSha256,
    terraformConfiguration: fixture.options.terraformConfiguration,
    now,
  }), /not attested/);
});

test("append-only audit requires every broker mode mapping", () => {
  const fixture = makeAtomicBrokerFixture();
  const audit = generate(fixture);
  audit.broker.liveTaskDefinitionMappings.pop();
  assert.throws(() => validateBrokerPlan(fixture, audit), /broker mode mapping is incomplete/);
});

test("append-only audit rejects a broker mode mapped to the wrong family", () => {
  const fixture = makeAtomicBrokerFixture();
  const audit = generate(fixture);
  const mapping = audit.broker.liveTaskDefinitionMappings.find((entry) => entry.mode === "full-rls-admin-bootstrap");
  mapping.taskDefinitionArn = newArnFor(familyForMode("full-rls-role-verify"));
  assert.throws(() => validateBrokerPlan(fixture, audit), /per-mode current\/retained ARN sets/);
});

test("append-only audit requires atomic evidence for every retained broker mapping", () => {
  const fixture = makeAtomicBrokerFixture();
  const audit = generate(fixture);
  audit.plannedAtomicBrokerRollovers = [];
  assert.throws(() => validateBrokerPlan(fixture, audit), /lacks atomic rollover evidence/);
});

test("unrelated shared-cluster task-definition families remain visible and excluded from Stage B decisions", () => {
  const unrelatedFamily = "mscqr-backend";
  const fixture = makeAtomicBrokerFixture({ mutateReader: (reader) => {
    reader.listServices = () => [serviceArnFor(0)];
    reader.describeServices = () => ({ services: [serviceRecord(serviceArnFor(0), 0, newArnFor(unrelatedFamily))], failures: [] });
    reader.listTasks = () => [taskArnFor("RUNNING", 0), taskArnFor("PENDING", 0)];
    reader.describeTasks = (arns) => ({ tasks: arns.map((arn) => taskRecord(arn, arn.includes("running") ? "RUNNING" : "PENDING", newArnFor(unrelatedFamily))), failures: [] });
  } });
  const audit = generate(fixture);
  assert.equal(audit.services.length, 1);
  assert.equal(audit.services[0].stageBScoped, false);
  assert.equal(audit.runningTasks[0].stageBScoped, false);
  assert.equal(audit.pendingTasks[0].stageBScoped, false);
  assert.doesNotThrow(() => validateBrokerPlan(fixture, audit));
});

for (const [label, mutate, expected = /append-only reference audit/] of [
  ["missing current task-definition evidence", (audit) => { delete audit.currentTaskDefinitions; }],
  ["missing retained task-definition evidence", (audit) => { delete audit.retainedTaskDefinitions; }],
  ["missing service evidence", (audit) => { delete audit.services; }],
  ["missing RUNNING-task evidence", (audit) => { delete audit.runningTasks; }],
  ["missing PENDING-task evidence", (audit) => { delete audit.pendingTasks; }],
  ["extra current task-definition entry", (audit) => { audit.createOnlyTaskDefinitions.push({ ...audit.createOnlyTaskDefinitions[0], terraformAddress: "aws_ecs_task_definition.candidate[\"unknown\"]" }); }],
  ["missing retained generation", (audit) => { audit.retainedTaskDefinitions.pop(); }],
  ["stale retained ARN", (audit) => { audit.retainedTaskDefinitions[0].oldTaskDefinitionArn = oldArnFor("mscqr-production-unknown"); }],
  ["classification count mismatch", (audit) => { audit.currentTaskDefinitions.currentCreates += 1; }],
  ["missing audit schema version", (audit) => { delete audit.schemaVersion; }],
  ["wrong audit cluster identity", (audit) => { audit.clusterArn = "arn:aws:ecs:eu-west-2:368992683803:cluster/unrelated"; }],
  ["missing audit caller identity", (audit) => { delete audit.callerArn; }],
  ["wrong audit caller identity", (audit) => { audit.callerArn = "arn:aws:iam::368992683803:user/untrusted"; }],
  ["forged audit caller identity", (audit) => { audit.callerArn = callerArn.replace("test-session", "forged-session"); }, /not attested/],
  ["service reference outside the current/retained sets", (audit) => { audit.services.push({ serviceName: "unexpected", taskDefinition: newArnFor("mscqr-production-unknown") }); }],
  ["RUNNING task reference outside the current/retained sets", (audit) => { audit.runningTasks.push({ taskArn: "arn:aws:ecs:eu-west-2:368992683803:task/unknown/running", taskDefinitionArn: newArnFor("mscqr-production-unknown"), lastStatus: "RUNNING", desiredStatus: "RUNNING", group: "service:unknown" }); }],
  ["PENDING task reference outside the current/retained sets", (audit) => { audit.pendingTasks.push({ taskArn: "arn:aws:ecs:eu-west-2:368992683803:task/unknown/pending", taskDefinitionArn: newArnFor("mscqr-production-unknown"), lastStatus: "PENDING", desiredStatus: "PENDING", group: "service:unknown" }); }],
  ["broker evidence without live mappings", (audit) => { delete audit.broker.liveTaskDefinitionMappings; }],
]) {
  test(`append-only audit binding rejects ${label}`, () => {
    const fixture = makeAtomicBrokerFixture();
    const audit = generate(fixture);
    mutate(audit);
    assert.throws(() => validateBrokerPlan(fixture, audit), expected);
  });
}

test("initial broker create passes with plan-only package proof", () => {
  const fixture = makeInitialBrokerCreateFixture();
  assert.doesNotThrow(() => assertStageBPlan(fixture.plan, { terraformConfiguration: fixture.options.terraformConfiguration }));
});

test("initial broker create does not require a reference audit", () => {
  const fixture = makeInitialBrokerCreateFixture();
  assert.doesNotThrow(() => assertStageBPlan(fixture.plan, { terraformConfiguration: fixture.options.terraformConfiguration }));
});

test("initial broker create reaches PLAN_CAPTURED without update-only broker validation", () => {
  const fixture = makeInitialBrokerCreateFixture({
    mutatePlan: (plan) => {
      plan.resource_changes.push(
        { address: "aws_iam_policy.broker", type: "aws_iam_policy", change: { actions: ["create"], before: null, after: { name: "mscqr-production-rls-approval-broker-runtime", path: "/", arn: "arn:aws:iam::368992683803:policy/mscqr-production-rls-approval-broker-runtime", id: "arn:aws:iam::368992683803:policy/mscqr-production-rls-approval-broker-runtime" }, after_unknown: { policy: true } } },
        { address: "aws_lambda_alias.reviewed", type: "aws_lambda_alias", change: { actions: ["create"], before: null, after: { function_name: "mscqr-production-rls-approval-broker", name: STAGE_B.brokerAliasQualifier, function_version: "1" } } },
      );
    },
  });
  const result = assertStageBPlanCapture(fixture.plan, { terraformConfiguration: fixture.options.terraformConfiguration });
  assert.equal(result.brokerCapture.brokerOperation, "initial-create");
  assert.equal(result.brokerCapture.brokerReferenceValidationPending, false);
  assert.equal(result.brokerCapture.brokerUpdatePresent, false);
  assert.deepEqual(result.brokerCapture.brokerActions, ["create"]);
});

test("initial broker create permits retained no-ops during append-only recovery", () => {
  const fixture = makeAtomicBrokerFixture({ brokerActions: ["create"] });
  assert.doesNotThrow(() => assertStageBPlan(fixture.plan, { terraformConfiguration: fixture.options.terraformConfiguration }));
});

test("initial broker create rejects a wrong ZIP source_code_hash", () => {
  const fixture = makeInitialBrokerCreateFixture({
    mutatePlan: (plan) => {
      plan.resource_changes.find((item) => item.address === "aws_lambda_function.broker").change.after.source_code_hash = "wrong";
    },
  });
  assert.throws(() => assertStageBPlan(fixture.plan, { terraformConfiguration: fixture.options.terraformConfiguration }), /source_code_hash/);
});

test("initial broker create rejects a wrong release-package checksum", () => {
  const fixture = makeInitialBrokerCreateFixture({
    mutatePlan: (plan) => { plan.variables.package_checksum_sha256.value = "d".repeat(64); },
  });
  assert.throws(() => assertStageBPlan(fixture.plan, { terraformConfiguration: fixture.options.terraformConfiguration }), /approval JSON does not match/);
});

test("initial broker create rejects a missing broker approval mapping", () => {
  const fixture = makeInitialBrokerCreateFixture({
    mutatePlan: (plan) => { plan.configuration.root_module.resources[0].expressions.environment[0].variables.references = [STAGE_B_BROKER_TASK_DEFINITION_REFERENCE]; },
  });
  assert.throws(() => assertStageBPlan(fixture.plan, { terraformConfiguration: fixture.options.terraformConfiguration }), /approval local reference/);
});

test("broker no-op remains accepted without update-only audit proof", () => {
  const fixture = makeInitialBrokerCreateFixture({
    mutatePlan: (plan) => { plan.resource_changes.find((item) => item.address === "aws_lambda_function.broker").change.actions = ["no-op"]; },
  });
  assert.doesNotThrow(() => assertStageBPlan(fixture.plan, { terraformConfiguration: fixture.options.terraformConfiguration }));
});

test("unsupported broker delete and replacement actions fail closed", () => {
  for (const actions of [["delete"], ["delete", "create"]]) {
    const fixture = makeAtomicBrokerFixture({ brokerActions: actions });
    assert.throws(() => assertStageBPlan(fixture.plan, { terraformConfiguration: fixture.options.terraformConfiguration }), /unsupported/);
  }
  const malformed = makeAtomicBrokerFixture({ brokerActions: [] });
  assert.throws(() => assertStageBPlan(malformed.plan, { terraformConfiguration: malformed.options.terraformConfiguration }), /missing or malformed/);
});

test("broker-lag retry includes current no-op in atomic rollover evidence", () => {
  const fixture = makeBrokerLagRetryFixture();
  const audit = generate(fixture);
  assert.equal(audit.noOpTaskDefinitions.some((entry) => entry.terraformAddress === executorAddressForMode("full-rls-admin-bootstrap")), true);
  assert.equal(audit.plannedAtomicBrokerRollovers.some((entry) => entry.taskDefinitionTerraformAddress === executorAddressForMode("full-rls-admin-bootstrap")), true);
  validateBrokerPlan(fixture, audit);
});

test("broker-lag retry rejects a stale current no-op image", () => {
  const fixture = makeBrokerLagRetryFixture();
  const change = fixture.plan.resource_changes.find((item) => item.address === executorAddressForMode("full-rls-admin-bootstrap"));
  const staleDefinitions = JSON.stringify([{ image: imageFor("mscqr-worker"), environment: [
    { name: "RELEASE_GIT_SHA", value: releaseSha },
    { name: "SOURCE_CONTRACT_SHA256", value: sourceContractSha256 },
    { name: "MIGRATION_SET_DIGEST", value: migrationSetDigest },
    { name: "PACKAGE_CHECKSUM_SHA256", value: packageChecksum },
  ] }]);
  change.change.before.container_definitions = staleDefinitions;
  change.change.after.container_definitions = staleDefinitions;
  fixture.plan.planned_values.root_module.resources.find((item) => item.address === change.address).values.container_definitions = staleDefinitions;
  fixture.planBytes = Buffer.from(JSON.stringify(fixture.plan));
  fixture.planJsonSha256 = sha256(fixture.planBytes);
  assert.throws(() => generate(fixture), /image digest is stale/);
});

test("broker-lag retry rejects a current no-op ARN in retained history", () => {
  const fixture = makeBrokerLagRetryFixture();
  const change = fixture.plan.resource_changes.find((item) => item.address === executorAddressForMode("full-rls-admin-bootstrap"));
  const retainedArn = oldArnFor(familyForMode("full-rls-admin-bootstrap"));
  change.change.before.arn = retainedArn;
  change.change.after.arn = retainedArn;
  const planned = fixture.plan.planned_values.root_module.resources.find((item) => item.address === change.address);
  planned.values.arn = retainedArn;
  fixture.planBytes = Buffer.from(JSON.stringify(fixture.plan));
  fixture.planJsonSha256 = sha256(fixture.planBytes);
  assert.throws(() => generate(fixture), /uses a retained ARN/);
});

test("broker-lag retry rejects a live broker ARN outside retained history", () => {
  const fixture = makeBrokerLagRetryFixture();
  const original = fixture.reader.getFunctionConfiguration;
  fixture.reader.getFunctionConfiguration = () => {
    const config = original();
    const variables = config.Environment.Variables;
    const mappings = JSON.parse(variables.BROKER_TASK_DEFINITIONS_JSON);
    mappings["full-rls-admin-bootstrap"] = `${newArnFor(familyForMode("full-rls-admin-bootstrap")).slice(0, -1)}99`;
    variables.BROKER_TASK_DEFINITIONS_JSON = JSON.stringify(mappings);
    return config;
  };
  assert.throws(() => generate(fixture), /superseded|not an explicitly retained or current no-op revision/);
});

test("broker ZIP checksum and source_code_hash are independently validated", () => {
  const fixture = makeAtomicBrokerFixture();
  const audit = generate(fixture);
  audit.broker.brokerZipFileSha256 = "0".repeat(64);
  audit.plannedAtomicPackageChecksumTransition = null;
  const auditBytes = Buffer.from(JSON.stringify(audit));
  assert.throws(() => assertStageBPlan(fixture.plan, {
    referenceAudit: audit,
    referenceAuditBytes: auditBytes,
    referenceAuditSha256: sha256(auditBytes),
    planJsonBytes: fixture.planBytes,
    planJsonSha256: fixture.planJsonSha256,
    terraformConfiguration: fixture.options.terraformConfiguration,
    trustedCallerArn: callerArn,
    now,
  }), /ZIP checksum/);
});

test("broker references to superseded revisions and unknown families fail closed", () => {
  const fixture = makeFixture({ mutateReader: (reader) => {
    const original = reader.getFunctionConfiguration;
    reader.getFunctionConfiguration = () => {
      const config = original();
      const variables = config.Environment.Variables;
      const taskDefinitions = JSON.parse(variables.BROKER_TASK_DEFINITIONS_JSON);
      taskDefinitions["full-rls-admin-bootstrap"] = oldArnFor(familyForMode("full-rls-admin-bootstrap"));
      variables.BROKER_TASK_DEFINITIONS_JSON = JSON.stringify(taskDefinitions);
      return config;
    };
  } });
  assert.throws(() => generate(fixture), /superseded task definition/);
  const unknown = makeFixture({ mutateReader: (reader) => {
    const original = reader.getFunctionConfiguration;
    reader.getFunctionConfiguration = () => {
      const config = original();
      const variables = config.Environment.Variables;
      const taskDefinitions = JSON.parse(variables.BROKER_TASK_DEFINITIONS_JSON);
      taskDefinitions["full-rls-admin-bootstrap"] = newArnFor("mscqr-production-unknown");
      variables.BROKER_TASK_DEFINITIONS_JSON = JSON.stringify(taskDefinitions);
      return config;
    };
  } });
  assert.throws(() => generate(unknown), /unexpected/);
});

test("atomic broker rollover in the same plan passes and is recorded explicitly", () => {
  const fixture = makeAtomicBrokerFixture();
  const audit = generate(fixture);
  assert.equal(audit.allOldRevisionsUnreferenced, false);
  assert.deepEqual(audit.plannedAtomicBrokerRollovers, [{
    brokerTerraformAddress: "aws_lambda_function.broker",
    taskDefinitionTerraformAddress: canaryAddress,
    mode: "full-rls-application-canary",
    family: familyForMode("full-rls-application-canary"),
    oldTaskDefinitionArn: oldArnFor(familyForMode("full-rls-application-canary")),
    brokerEnvironmentReference: STAGE_B_BROKER_TASK_DEFINITION_REFERENCE,
    taskDefinitionArnReference: `${canaryAddress}.arn`,
    planJsonSha256: fixture.planJsonSha256,
  }]);
  const canaryRetainedAddress = retainedAddressFor(canaryAddress);
  const canary = audit.retainedTaskDefinitions.find((entry) => entry.terraformAddress === canaryRetainedAddress);
  assert.deepEqual(canary.brokerReferenceModes, ["full-rls-application-canary"]);
  assert.equal(canary.brokerReferenceStatus, "planned-atomic-broker-rollover-v1");
  const auditBytes = Buffer.from(JSON.stringify(audit));
  assert.doesNotThrow(() => assertStageBPlan(fixture.plan, {
    referenceAudit: audit,
    referenceAuditBytes: auditBytes,
    referenceAuditSha256: sha256(auditBytes),
    planJsonBytes: fixture.planBytes,
    planJsonSha256: fixture.planJsonSha256,
    terraformConfiguration: fixture.options.terraformConfiguration,
    trustedCallerArn: callerArn,
    now,
  }));
});

test("current rollover broker mapping preserves rollover classification through plan binding", () => {
  const fixture = makeAtomicBrokerFixture({
    mutatePlan: (plan) => {
      const current = plan.resource_changes.find((item) => item.address === canaryAddress);
      const retained = plan.resource_changes.find((item) => item.address === retainedAddressFor(canaryAddress));
      current.change = {
        ...current.change,
        actions: ["delete", "create"],
        before: { ...structuredClone(retained.change.before), arn: retained.change.before.arn.replace(":1", ":5") },
        replace_paths: [["container_definitions"]],
      };
    },
    mutateReader: (reader) => {
      const original = reader.getFunctionConfiguration;
      reader.getFunctionConfiguration = () => {
        const configuration = original();
        const taskDefinitions = JSON.parse(configuration.Environment.Variables.BROKER_TASK_DEFINITIONS_JSON);
        taskDefinitions["full-rls-application-canary"] = oldArnFor(familyForMode("full-rls-application-canary")).replace(":1", ":5");
        configuration.Environment.Variables.BROKER_TASK_DEFINITIONS_JSON = JSON.stringify(taskDefinitions);
        return configuration;
      };
    },
  });
  const audit = generate(fixture);
  assert.equal(audit.oldTaskDefinitions.length, 1);
  assert.equal(audit.oldTaskDefinitions.every((entry) => entry.classification === "rollover"), true);
  assert.equal(audit.oldTaskDefinitions.filter((entry) => entry.brokerReferenceStatus === "planned-atomic-broker-rollover-v1").length, 1);
  const auditBytes = Buffer.from(JSON.stringify(audit));
  assert.doesNotThrow(() => assertStageBPlan(fixture.plan, {
    referenceAudit: audit,
    referenceAuditBytes: auditBytes,
    referenceAuditSha256: sha256(auditBytes),
    planJsonBytes: fixture.planBytes,
    planJsonSha256: fixture.planJsonSha256,
    terraformConfiguration: fixture.options.terraformConfiguration,
    trustedCallerArn: callerArn,
    now,
  }));
});

test("executor admin-bootstrap atomic rollover passes with a collection dependency", () => {
  const mode = "full-rls-admin-bootstrap";
  const fixture = makeAtomicBrokerFixture({ mode });
  const audit = generate(fixture);
  assert.deepEqual(audit.plannedAtomicBrokerRollovers.map((item) => item.mode), [mode]);
});

test("another executor mode passes with the same collection dependency proof", () => {
  const mode = "full-rls-role-verify";
  const fixture = makeAtomicBrokerFixture({ mode });
  const audit = generate(fixture);
  assert.deepEqual(audit.plannedAtomicBrokerRollovers.map((item) => item.mode), [mode]);
});

test("executor collection dependency is accepted only for the matching mode", () => {
  const mode = "full-rls-admin-bootstrap";
  const fixture = makeAtomicBrokerFixture({ mode });
  assert.doesNotThrow(() => assertStageBAtomicBrokerPlan(
    fixture.plan,
    executorAddressForMode(mode),
    mode,
    fixture.options.terraformConfiguration,
  ));
  assert.throws(
    () => assertStageBAtomicBrokerPlan(
      fixture.plan,
      executorAddressForMode("full-rls-role-verify"),
      mode,
      fixture.options.terraformConfiguration,
    ),
    /task-definition mode does not match/,
  );
});

test("missing executor collection dependency fails closed", () => {
  assert.throws(
    () => generate(makeAtomicBrokerFixture({ mode: "full-rls-admin-bootstrap", omitExecutorCollectionDependency: true })),
    /Terraform dependency/,
  );
});

test("collection dependency covers the exact candidate canary instance", () => {
  const fixture = makeAtomicBrokerFixture({ mutatePlan: (plan) => {
    plan.relevant_attributes = [{ resource: "aws_ecs_task_definition.candidate", attribute: [] }];
  } });
  assert.doesNotThrow(() => assertStageBAtomicBrokerPlan(
    fixture.plan,
    canaryAddress,
    "full-rls-application-canary",
    fixture.options.terraformConfiguration,
  ));
  assert.doesNotThrow(() => assertTerraformDependencyCoversAddress({
    relevantAttributes: fixture.plan.relevant_attributes,
    expectedResourceAddress: canaryAddress,
  }));
});

test("collection dependency does not cover an executor instance", () => {
  assert.throws(
    () => assertTerraformDependencyCoversAddress({
      relevantAttributes: [{ resource: "aws_ecs_task_definition.candidate", attribute: [] }],
      expectedResourceAddress: executorAddressForMode("full-rls-verification"),
    }),
    /Terraform dependency to/,
  );
});

test("indexed dependencies accept attribute and instance-level Terraform forms", () => {
  assert.doesNotThrow(() => assertTerraformDependencyCoversAddress({
    relevantAttributes: [{ resource: canaryAddress, attribute: ["arn"] }],
    expectedResourceAddress: canaryAddress,
  }));
  assert.doesNotThrow(() => assertTerraformDependencyCoversAddress({
    relevantAttributes: [{ resource: canaryAddress, attribute: [] }],
    expectedResourceAddress: canaryAddress,
  }));
  assert.throws(() => assertTerraformDependencyCoversAddress({
    relevantAttributes: [{ resource: 'aws_ecs_task_definition.candidate["backend"]', attribute: ["arn"] }],
    expectedResourceAddress: canaryAddress,
  }), /Terraform dependency to/);
});

test("structured dependency matching rejects unrelated or retained collections", () => {
  for (const resource of [
    "aws_ecs_task_definition.executor",
    "aws_ecs_task_definition.candidate_retained",
    "aws_lambda_function.broker",
  ]) {
    assert.throws(
      () => assertTerraformDependencyCoversAddress({
        relevantAttributes: [{ resource, attribute: [] }],
        expectedResourceAddress: canaryAddress,
      }),
      /Terraform dependency to/,
    );
  }
  assert.throws(
    () => assertTerraformDependencyCoversAddress({
      relevantAttributes: [{ resource: "aws_ecs_task_definition.candidate", attribute: [] }],
      expectedResourceAddress: 'aws_ecs_task_definition.candidate_retained["aaaaaaaa-canary"]',
    }),
    /Terraform dependency to/,
  );
  assert.throws(
    () => assertTerraformDependencyCoversAddress({
      relevantAttributes: [{ resource: "aws_lambda_function.candidate", attribute: [] }],
      expectedResourceAddress: canaryAddress,
    }),
    /Terraform dependency to/,
  );
});

test("complete broker mode mapping passes", () => {
  const fixture = makeAtomicBrokerFixture({ mode: "full-rls-admin-bootstrap" });
  assert.doesNotThrow(() => assertStageBBrokerTaskDefinitionMapping(fixture.plan, fixture.options.terraformConfiguration));
});

test("broker task-definition mapping reference matches Terraform source exactly", () => {
  assert.match(terraformConfigurationSource, /BROKER_TASK_DEFINITIONS_JSON\s*=\s*jsonencode\(local\.active_broker_task_definition_arns\)/);
  const fixture = makeAtomicBrokerFixture({ mode: "full-rls-admin-bootstrap" });
  const broker = fixture.plan.configuration.root_module.resources
    .find((resource) => resource.address === "aws_lambda_function.broker");
  assert.deepEqual(
    broker.expressions.environment[0].variables.references.filter((reference) => reference.includes("broker_task_definition_arns")),
    [STAGE_B_BROKER_TASK_DEFINITION_REFERENCE],
  );
  assert.doesNotThrow(() => assertStageBBrokerTaskDefinitionMapping(fixture.plan, fixture.options.terraformConfiguration));
});

test("active broker task-definition local is the exact reviewed conditional", () => {
  assert.doesNotThrow(() => assertStageBActiveBrokerTaskDefinitionLocal(terraformConfigurationSource));
  assert.equal(
    STAGE_B_ACTIVE_BROKER_TASK_DEFINITION_LOCAL_EXPRESSION,
    "var.stage_b_recovery_only ? var.stage_b_recovery_task_definition_arns : local.broker_task_definition_arns",
  );
  const fixture = makeAtomicBrokerFixture({ mode: "full-rls-admin-bootstrap" });
  assert.doesNotThrow(() => assertStageBBrokerTaskDefinitionMapping(fixture.plan, fixture.options.terraformConfiguration));
});

test("active broker task-definition local rejects alternate branches and overrides", () => {
  const invalidExpressions = [
    "merge(local.broker_task_definition_arns, { override = \"unexpected\" })",
    "merge(local.broker_task_definition_arns, var.stage_b_recovery_task_definition_arns)",
    "var.stage_b_recovery_task_definition_arns",
    "local.broker_task_definition_arns",
    "var.stage_b_recovery_task_definition_arns ? var.stage_b_recovery_only : local.broker_task_definition_arns",
    "var.stage_b_recovery_only ? local.broker_task_definition_arns : var.stage_b_recovery_task_definition_arns",
    "var.other_selector ? var.stage_b_recovery_task_definition_arns : local.broker_task_definition_arns",
    "var.stage_b_recovery_only ? var.other_recovery_task_definition_arns : local.broker_task_definition_arns",
    "var.stage_b_recovery_only ? var.stage_b_recovery_task_definition_arns : local.other_broker_task_definition_arns",
  ];
  for (const expression of invalidExpressions) {
    const fixture = makeAtomicBrokerFixture({
      mode: "full-rls-admin-bootstrap",
      terraformConfiguration: withActiveBrokerMapping(expression),
    });
    assert.throws(
      () => assertStageBBrokerTaskDefinitionMapping(fixture.plan, fixture.options.terraformConfiguration),
      /Active broker task-definition local source is missing or malformed/,
    );
  }
  const missing = makeAtomicBrokerFixture({
    mode: "full-rls-admin-bootstrap",
    terraformConfiguration: terraformConfigurationSource.replace(/^\s*active_broker_task_definition_arns\s*=.*\n/m, ""),
  });
  assert.throws(
    () => assertStageBBrokerTaskDefinitionMapping(missing.plan, missing.options.terraformConfiguration),
    /Active broker task-definition local source is missing or malformed/,
  );
});

test("stale, arbitrary, and missing broker mapping references fail closed", () => {
  for (const references of [
    ["local.broker_task_definition_arns", "local.broker_approval_expected"],
    ["local.unreviewed", "local.broker_approval_expected"],
    ["local.broker_approval_expected"],
  ]) {
    const fixture = makeAtomicBrokerFixture({ mode: "full-rls-admin-bootstrap" });
    fixture.plan.configuration.root_module.resources
      .find((resource) => resource.address === "aws_lambda_function.broker")
      .expressions.environment[0].variables.references = references;
    assert.throws(
      () => assertStageBAtomicBrokerPlan(
        fixture.plan,
        canaryAddress,
        "full-rls-application-canary",
        fixture.options.terraformConfiguration,
      ),
      /Broker atomic rollover Terraform reference to local\.active_broker_task_definition_arns is missing\./,
    );
  }
});

test("executor for_each fixture matches the Terraform source and exact audit contract", () => {
  assert.match(
    terraformConfigurationSource,
    /resource "aws_ecs_task_definition" "executor"[\s\S]*?for_each\s*=\s*local\.executor_definitions_for_resources/,
  );
  const fixture = makeAtomicBrokerFixture({ mode: "full-rls-admin-bootstrap" });
  const executor = fixture.plan.configuration.root_module.resources
    .find((resource) => resource.address === executorCollectionAddress);
  assert.deepEqual(executor.for_each_expression.references, ["local.executor_definitions_for_resources"]);
  assert.deepEqual(executor.for_each_expression.references, STAGE_B_EXECUTOR_FOR_EACH_REFERENCES);
});

test("candidate for_each fixture matches the Terraform source and exact audit contract", () => {
  assert.match(
    terraformConfigurationSource,
    /resource "aws_ecs_task_definition" "candidate"[\s\S]*?for_each\s*=\s*local\.candidate_definitions_for_resources/,
  );
  const fixture = makeAtomicBrokerFixture({ mode: "full-rls-admin-bootstrap" });
  const candidate = fixture.plan.configuration.root_module.resources
    .find((resource) => resource.address === "aws_ecs_task_definition.candidate");
  assert.deepEqual(candidate.for_each_expression.references, [...STAGE_B_CANDIDATE_FOR_EACH_REFERENCES]);
});

test("indexed candidate dependency passes the exact candidate for_each contract", () => {
  const fixture = makeAtomicBrokerFixture({ mode: "full-rls-application-canary" });
  assert.deepEqual(fixture.plan.relevant_attributes, [{ resource: canaryAddress, attribute: ["arn"] }]);
  assert.doesNotThrow(() => assertStageBAtomicBrokerPlan(
    fixture.plan,
    canaryAddress,
    "full-rls-application-canary",
    fixture.options.terraformConfiguration,
  ));
});

test("stale, arbitrary, missing, empty, and extra executor for_each references fail closed", () => {
  for (const references of [
    ["local.executor_definitions"],
    ["local.unreviewed"],
    undefined,
    [],
    ["local.executor_definitions_for_resources", "local.unreviewed"],
  ]) {
    const fixture = makeAtomicBrokerFixture({ mode: "full-rls-admin-bootstrap" });
    const executor = fixture.plan.configuration.root_module.resources
      .find((resource) => resource.address === executorCollectionAddress);
    if (references === undefined) delete executor.for_each_expression;
    else executor.for_each_expression.references = references;
    assert.throws(
      () => assertStageBBrokerTaskDefinitionMapping(fixture.plan, fixture.options.terraformConfiguration),
      /for_each metadata is missing or malformed/,
    );
  }
});

test("candidate for_each references are required for collection and indexed dependencies", () => {
  for (const references of [
    ["local.candidate_definitions"],
    ["local.unreviewed"],
    [],
    ["local.candidate_definitions_for_resources", "local.unreviewed"],
  ]) {
    for (const relevantAttributes of [
      [{ resource: "aws_ecs_task_definition.candidate", attribute: [] }],
      [{ resource: canaryAddress, attribute: ["arn"] }],
    ]) {
      const fixture = makeAtomicBrokerFixture({
        mode: "full-rls-application-canary",
        mutatePlan: (plan) => { plan.relevant_attributes = relevantAttributes; },
      });
      const candidate = fixture.plan.configuration.root_module.resources
        .find((resource) => resource.address === "aws_ecs_task_definition.candidate");
      candidate.for_each_expression.references = references;
      assert.throws(
        () => assertStageBAtomicBrokerPlan(
          fixture.plan,
          canaryAddress,
          "full-rls-application-canary",
          fixture.options.terraformConfiguration,
        ),
        /candidate for_each metadata is missing or malformed/,
      );
    }
  }
});

test("executor family reference remains exact and singular", () => {
  for (const references of [[], ["each.value.other_family"], ["each.value.family", "each.value.family"]]) {
    const fixture = makeAtomicBrokerFixture({ mode: "full-rls-admin-bootstrap" });
    const executor = fixture.plan.configuration.root_module.resources
      .find((resource) => resource.address === executorCollectionAddress);
    executor.expressions.family.references = references;
    assert.throws(
      () => assertStageBBrokerTaskDefinitionMapping(fixture.plan, fixture.options.terraformConfiguration),
      /for_each metadata is missing or malformed/,
    );
  }
});

test("executor mapping still requires exactly the reviewed twelve current task-definition addresses", () => {
  const missing = makeAtomicBrokerFixture({ mode: "full-rls-admin-bootstrap" });
  missing.plan.planned_values.root_module.resources = missing.plan.planned_values.root_module.resources
    .filter((resource) => resource.address !== 'aws_ecs_task_definition.executor["full-rls-admin-bootstrap"]');
  assert.throws(
    () => assertStageBBrokerTaskDefinitionMapping(missing.plan, missing.options.terraformConfiguration),
    /requires all twelve current task-definition mappings/,
  );

  const extra = makeAtomicBrokerFixture({ mode: "full-rls-admin-bootstrap" });
  extra.plan.planned_values.root_module.resources.push({
    address: 'aws_ecs_task_definition.executor["unreviewed"]',
    type: "aws_ecs_task_definition",
    index: "unreviewed",
    values: { family: "unreviewed" },
  });
  assert.throws(
    () => assertStageBBrokerTaskDefinitionMapping(extra.plan, extra.options.terraformConfiguration),
    /executor mapping is incomplete or duplicated/,
  );
});

test("broker mode mapping accepts supported plans without identity metadata", () => {
  const fixture = makeAtomicBrokerFixture({ mode: "full-rls-admin-bootstrap" });
  for (const resource of fixture.plan.planned_values.root_module.resources) delete resource.identity;
  assert.doesNotThrow(() => assertStageBBrokerTaskDefinitionMapping(fixture.plan, fixture.options.terraformConfiguration));
});

test("swapped executor mode mappings fail closed", () => {
  const swapped = `merge(
    { full-rls-admin-bootstrap = aws_ecs_task_definition.executor["full-rls-role-verify"].arn,
      full-rls-role-verify = aws_ecs_task_definition.executor["full-rls-admin-bootstrap"].arn },
    { full-rls-application-canary = aws_ecs_task_definition.candidate["canary"].arn }
  )`;
  assert.throws(
    () => generate(makeAtomicBrokerFixture({ mode: "full-rls-admin-bootstrap", terraformConfiguration: withBrokerMapping(swapped) })),
    /per-mode mapping/,
  );
});

test("duplicate executor target mappings fail closed", () => {
  const duplicate = `merge(
    { full-rls-admin-bootstrap = aws_ecs_task_definition.executor["full-rls-admin-bootstrap"].arn,
      full-rls-role-verify = aws_ecs_task_definition.executor["full-rls-admin-bootstrap"].arn },
    { full-rls-application-canary = aws_ecs_task_definition.candidate["canary"].arn }
  )`;
  assert.throws(
    () => generate(makeAtomicBrokerFixture({ mode: "full-rls-admin-bootstrap", terraformConfiguration: withBrokerMapping(duplicate) })),
    /per-mode mapping/,
  );
});

test("missing and unexpected executor modes fail closed", () => {
  const missing = `merge(
    { full-rls-admin-bootstrap = aws_ecs_task_definition.executor["full-rls-admin-bootstrap"].arn },
    { full-rls-application-canary = aws_ecs_task_definition.candidate["canary"].arn }
  )`;
  const unexpected = `merge(
    { unexpected = aws_ecs_task_definition.executor["full-rls-admin-bootstrap"].arn },
    { full-rls-application-canary = aws_ecs_task_definition.candidate["canary"].arn }
  )`;
  assert.throws(() => generate(makeAtomicBrokerFixture({ mode: "full-rls-admin-bootstrap", terraformConfiguration: withBrokerMapping(missing) })), /per-mode mapping/);
  assert.throws(() => generate(makeAtomicBrokerFixture({ mode: "full-rls-admin-bootstrap", terraformConfiguration: withBrokerMapping(unexpected) })), /per-mode mapping/);
});

test("collection-only executor dependency without the exact mapping fails closed", () => {
  const collectionOnly = `merge(
    { for mode, task in aws_ecs_task_definition.executor : mode => task },
    { full-rls-application-canary = aws_ecs_task_definition.candidate["canary"].arn }
  )`;
  assert.throws(
    () => generate(makeAtomicBrokerFixture({ mode: "full-rls-admin-bootstrap", terraformConfiguration: withBrokerMapping(collectionOnly) })),
    /per-mode mapping/,
  );
});

test("broker no-op with a superseded ARN fails closed", () => {
  assert.throws(() => generate(makeAtomicBrokerFixture({ brokerActions: ["no-op"] })), /requires aws_lambda_function\.broker actions/);
});

test("broker update without a task-definition reference fails closed", () => {
  const fixture = makeAtomicBrokerFixture({ mutatePlan: (plan) => { delete plan.configuration; delete plan.relevant_attributes; } });
  assert.throws(() => generate(fixture), /Terraform reference to local\.active_broker_task_definition_arns/);
});

test("broker mutation fails when a current task-definition mapping is absent", () => {
  const fixture = makeAtomicBrokerFixture({
    mutatePlan: (plan) => {
      plan.planned_values.root_module.resources = plan.planned_values.root_module.resources
        .filter((resource) => resource.address !== backendAddress);
    },
  });
  assert.throws(() => assertStageBPlan(fixture.plan, { terraformConfiguration: fixture.options.terraformConfiguration }), /Broker mutation requires all twelve current task-definition mappings/);
});

test("broker update referencing the wrong family fails closed", () => {
  const fixture = makeAtomicBrokerFixture({ mutateReader: (reader) => {
    const original = reader.getFunctionConfiguration;
    reader.getFunctionConfiguration = () => {
      const config = original();
      const variables = config.Environment.Variables;
      const taskDefinitions = JSON.parse(variables.BROKER_TASK_DEFINITIONS_JSON);
      taskDefinitions["full-rls-application-canary"] = oldArnFor(familyForMode("full-rls-admin-bootstrap"));
      variables.BROKER_TASK_DEFINITIONS_JSON = JSON.stringify(taskDefinitions);
      return config;
    };
  } });
  assert.throws(() => generate(fixture), /family is unexpected/);
});

test("live broker ARN must match the rollover before ARN", () => {
  const fixture = makeAtomicBrokerFixture({ mutatePlan: (plan) => {
    plan.resource_changes.find((item) => item.address === retainedAddressFor(canaryAddress)).change.before.arn = newArnFor(familyForMode("full-rls-application-canary"));
  } });
  assert.throws(() => generate(fixture), /not an explicitly retained|does not match the rollover before ARN/);
});

test("unrelated superseded broker reference fails closed", () => {
  const fixture = makeAtomicBrokerFixture({ mutateReader: (reader) => {
    const original = reader.getFunctionConfiguration;
    reader.getFunctionConfiguration = () => {
      const config = original();
      const variables = config.Environment.Variables;
      const taskDefinitions = JSON.parse(variables.BROKER_TASK_DEFINITIONS_JSON);
      taskDefinitions["full-rls-application-canary"] = oldArnFor(familyForMode("full-rls-admin-bootstrap"));
      variables.BROKER_TASK_DEFINITIONS_JSON = JSON.stringify(taskDefinitions);
      return config;
    };
  } });
  assert.throws(() => generate(fixture), /family is unexpected/);
});

test("malformed AWS responses fail closed", () => {
  const fixture = makeFixture({ mutateReader: (reader) => { reader.listTasks = () => null; } });
  assert.throws(() => generate(fixture), /task listing is malformed/);
});

test("recovery-only reference audit binds one concrete alias update and all release resources to no-op", () => {
  const fixture = makeFixture({ appendOnly: true });
  fixture.plan.variables.stage_b_recovery_only = { value: true };
  fixture.plan.variables.stage_b_recovery_alias_target_version = { value: "3" };
  for (const change of fixture.plan.resource_changes) {
    if (change.type === "aws_ecs_task_definition" && !change.address.includes("_retained[")) change.change.actions = ["no-op"];
  }
  fixture.plan.resource_changes.push({ address: "aws_lambda_alias.reviewed", mode: "managed", type: "aws_lambda_alias", change: { actions: ["update"], before: { function_version: "2" }, after: { function_version: "3" }, after_unknown: {} } });
  fixture.planBytes = Buffer.from(JSON.stringify(fixture.plan));
  fixture.planJsonSha256 = sha256(fixture.planBytes);
  const audit = generate(fixture, { recoveryAttestationSha256: "b".repeat(64) });
  assert.equal(audit.recoveryOnly, true);
  assert.equal(audit.recoveryAlias.liveVersion, "2");
  assert.equal(audit.recoveryAlias.targetVersion, "3");
  assert.equal(audit.recoveryNoOpResources.length, fixture.plan.resource_changes.length - 1);
  const auditBytes = Buffer.from(JSON.stringify(audit));
  assert.doesNotThrow(() => assertStageBPlan(fixture.plan, {
    referenceAudit: audit,
    referenceAuditBytes: auditBytes,
    referenceAuditSha256: sha256(auditBytes),
    planJsonBytes: fixture.planBytes,
    planJsonSha256: fixture.planJsonSha256,
    terraformConfiguration: terraformConfigurationSource,
    trustedCallerArn: callerArn,
    recoveryOnly: true,
    now,
  }));
});

test("generated audit is accepted by the existing Stage B plan validator", () => {
  const fixture = makeAtomicBrokerFixture();
  const audit = generate(fixture);
  const auditBytes = Buffer.from(JSON.stringify(audit));
  assert.doesNotThrow(() => assertStageBPlan(fixture.plan, {
    referenceAudit: audit,
    referenceAuditBytes: auditBytes,
    referenceAuditSha256: sha256(auditBytes),
    planJsonBytes: fixture.planBytes,
    planJsonSha256: fixture.planJsonSha256,
    now,
    terraformConfiguration: terraformConfigurationSource,
    trustedCallerArn: callerArn,
  }));
});

test("create-only audit is accepted by the existing Stage B plan validator", () => {
  const fixture = makeCreateOnlyFixture({ appendOnly: true });
  const audit = generate(fixture);
  const auditBytes = Buffer.from(JSON.stringify(audit));
  assert.doesNotThrow(() => assertStageBPlan(fixture.plan, {
    referenceAudit: audit,
    referenceAuditBytes: auditBytes,
    referenceAuditSha256: sha256(auditBytes),
    planJsonBytes: fixture.planBytes,
    planJsonSha256: fixture.planJsonSha256,
    now,
    terraformConfiguration: terraformConfigurationSource,
    trustedCallerArn: callerArn,
  }));
});

test("AWS reader uses argv arrays and only read-only commands", () => {
  const calls = [];
  const responses = {
    "sts get-caller-identity": { Arn: callerArn },
    "ecs list-services": { serviceArns: [] },
    "ecs describe-services": { services: [], failures: [] },
    "ecs list-tasks": { taskArns: [] },
    "ecs describe-tasks": { tasks: [], failures: [] },
    "ecs describe-task-definition": { taskDefinition: { taskDefinitionArn: oldArnFor("x"), family: "x", revision: 1, status: "ACTIVE" } },
    "lambda get-function-configuration": {},
    "lambda get-alias": {},
  };
  const reader = createAwsReader({
    region: "eu-west-2",
    clusterArn,
    run: (args) => { calls.push(args); return JSON.stringify(responses[args.slice(0, 2).join(" ")] || {}); },
  });
  reader.getCallerIdentity(); reader.listServices(); reader.describeServices([]); reader.listTasks("RUNNING"); reader.describeTasks([]); reader.describeTaskDefinition("safe"); reader.getFunctionConfiguration(brokerAliasArn); reader.getAlias();
  assert.deepEqual(new Set(calls.map((args) => args.slice(0, 2).join(" "))), new Set(Object.keys(responses)));
  assert.ok(calls.every((args) => args.every((value) => !/[;&|`$()]/.test(value))));
  const source = fs.readFileSync("scripts/aws/generate-production-green-stage-b-reference-audit.mjs", "utf8");
  assert.equal(source.includes("shell: true"), false);
  assert.equal(source.includes("child_process.exec("), false);
  assert.doesNotMatch(source, /iam\s+(?:put|create|delete|attach|detach)|ecs\s+(?:run|stop|update|delete|register)|lambda\s+(?:update|publish|delete|invoke)/);
  assert.throws(() => createAwsReader({
    region: "eu-west-2",
    clusterArn: `${clusterArn};touch /tmp/should-not-run`,
    run: () => JSON.stringify({ serviceArns: [] }),
  }), /exact production region and cluster/);
});
