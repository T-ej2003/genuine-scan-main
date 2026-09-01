const ACCOUNT = "368992683803";
const REGION = "eu-west-2";
const CLUSTER = "mscqr-prod-euw2-main";
const SERVICE = "mscqr-backend-servi-euw2";
const CONTAINER = "backend";

const parseJson = (run, args) => JSON.parse(run([...args, "--output", "json", "--no-cli-pager"]));

export function createProductionVerifierEcsAdapter(run, interactive) {
  return {
    describeService: async () => parseJson(run, ["ecs", "describe-services", "--cluster", CLUSTER, "--services", SERVICE]).services?.[0],
    listTasks: async () => parseJson(run, ["ecs", "list-tasks", "--cluster", CLUSTER, "--service-name", SERVICE, "--desired-status", "RUNNING"]),
    describeTasks: async ({ taskArns, includeTags }) => parseJson(run, ["ecs", "describe-tasks", "--cluster", CLUSTER, "--tasks", ...taskArns, ...(includeTags ? ["--include", "TAGS"] : [])]),
    executeCommand: async ({ taskArn, container, command, inputFile }) => interactive
      ? interactive({ cluster: CLUSTER, taskArn, container, command, inputFile })
      : parseJson(run, ["ecs", "execute-command", "--cluster", CLUSTER, "--task", taskArn, "--container", container, "--interactive", "--command", command]),
  };
}

export function createLazyProductionVerifierEcsAdapter(getRun, getInteractive) {
  return new Proxy({}, { get: (_target, property) => (...args) => createProductionVerifierEcsAdapter(getRun(), getInteractive?.())[property](...args) });
}

const quote = (value) => `'${String(value).replaceAll("'", "'\\''")}'`;
export const productionOverlapRuntimeProofCommand = ({ sourceSha, rotationId, deploymentSha, healthUrl, invocationRef }) => {
  if (!/^[a-f0-9]{40}$/.test(sourceSha || "") || !/^[A-Za-z0-9._-]{8,128}$/.test(rotationId || "") || !/^https:\/\//.test(healthUrl || "")) throw new Error("Runtime proof identity is invalid.");
  const proofPath = `/app/uploads/.mscqr-rotation-proof-${rotationId}.json`;
  return [
    "stty -echo",
    `trap 'rm -f ${quote(proofPath)}; stty echo' EXIT HUP INT TERM`,
    `ROTATION_RUNTIME_PHASE=overlap ROTATION_ID=${quote(rotationId)} ROTATION_DEPLOYMENT_SHA=${quote(deploymentSha || sourceSha)} ROTATION_RUNTIME_INVOCATION_REF=${quote(invocationRef || `cutover-${rotationId}`)} node /app/scripts/security/verify-production-rotation-runtime.mjs --fixture-stdin --output ${quote(proofPath)} --health-url ${quote(healthUrl)} --expected-release-sha ${quote(sourceSha)}`,
    "status=$?",
    `if [ \"$status\" -eq 0 ]; then printf '\\nMSCQR_PROOF_BEGIN\\n'; cat ${quote(proofPath)}; printf '\\nMSCQR_PROOF_END\\n'; fi`,
    "exit $status",
  ].join("; ");
};
