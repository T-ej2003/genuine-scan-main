import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
export function renderTaskDefinition(env = process.env) {
  const bindings = {
    execution_role_arn: requiredEnv(env, "VICTORIA_RECOVERY_EXECUTION_ROLE_ARN"),
    task_role_arn: requiredEnv(env, "VICTORIA_RECOVERY_TASK_ROLE_ARN"),
    image: requiredEnv(env, "VICTORIA_RECOVERY_IMAGE"),
    database_host: requiredEnv(env, "VICTORIA_RDS_HOST"),
    evidence_bucket: requiredEnv(env, "VICTORIA_RECOVERY_EVIDENCE_BUCKET"),
    signing_key_arn: requiredEnv(env, "VICTORIA_RECOVERY_SIGNING_KEY_ARN"),
    log_group: requiredEnv(env, "VICTORIA_RECOVERY_LOG_GROUP"),
  };
  if (!/^368992683803\.dkr\.ecr\.eu-west-2\.amazonaws\.com\/mscqr-victoria-recovery@sha256:[a-f0-9]{64}$/.test(bindings.image)
      || !/^arn:aws:iam::368992683803:role\/mscqr-production-victoria-recovery-(?:task|execution)$/.test(bindings.task_role_arn)
      || !/^arn:aws:iam::368992683803:role\/mscqr-production-victoria-recovery-execution$/.test(bindings.execution_role_arn)
      || !/^[a-z0-9][a-z0-9.-]*\.eu-west-2\.rds\.amazonaws\.com$/.test(bindings.database_host)
      || !/^arn:aws:kms:eu-west-2:368992683803:key\/[a-f0-9-]{36}$/.test(bindings.signing_key_arn)
      || !/^[a-z0-9][a-z0-9-]{2,62}$/.test(bindings.evidence_bucket)
      || !/^\/ecs\/mscqr-production\/victoria-recovery$/.test(bindings.log_group)) throw new Error("RECOVERY_TASK_DEFINITION_BINDING_INVALID");
  const template = fs.readFileSync(path.join(root, "infra/aws/terraform/production-victoria-recovery/task-definition.json"), "utf8");
  return JSON.parse(template.replace(/\$\{([a-z_]+)\}/g, (_match, key) => {
    if (!(key in bindings)) throw new Error("RECOVERY_TASK_DEFINITION_PLACEHOLDER_INVALID");
    return bindings[key];
  }));
}

function requiredEnv(env, name) {
  const value = env[name];
  if (!value || value.startsWith("--")) throw new Error(`${name}_MISSING`);
  return value;
}

export function registerFixedTaskDefinition(env = process.env) {
  const task = renderTaskDefinition(env);
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "victoria-recovery-taskdef-"));
  fs.chmodSync(directory, 0o700);
  const file = path.join(directory, "task-definition.json");
  try {
    fs.writeFileSync(file, JSON.stringify(task), { mode: 0o600, flag: "wx" });
    const output = execFileSync("aws", ["ecs", "register-task-definition", "--region", "eu-west-2", "--cli-input-json", `file://${file}`], {
      encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], env,
    });
    const taskDefinition = JSON.parse(output).taskDefinition;
    if (taskDefinition?.family !== "mscqr-production-victoria-recovery" || !Number.isInteger(taskDefinition.revision)) throw new Error("RECOVERY_TASK_DEFINITION_REGISTER_FAILED");
    return { taskDefinitionArn: taskDefinition.taskDefinitionArn, revision: taskDefinition.revision };
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
}

if (import.meta.url === pathToFileURL(process.argv[1] || "").href) {
  try { process.stdout.write(`${JSON.stringify(registerFixedTaskDefinition())}\n`); }
  catch (error) { process.stderr.write(`${/^[A-Z0-9_]+$/.test(error.message) ? error.message : "RECOVERY_TASK_DEFINITION_FAILED"}\n`); process.exitCode = 1; }
}
