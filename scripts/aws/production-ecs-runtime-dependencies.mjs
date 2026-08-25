import crypto from "node:crypto";

export const RUNTIME_ACCOUNT = "368992683803";
export const RUNTIME_REGION = "eu-west-2";
export const RUNTIME_ROLE_ARN = new RegExp(`^arn:aws:iam::${RUNTIME_ACCOUNT}:role/[A-Za-z0-9_+=,.@/-]+$`);
const SECRET_ARN = new RegExp(`^arn:aws:secretsmanager:${RUNTIME_REGION}:${RUNTIME_ACCOUNT}:secret:[A-Za-z0-9/_+=.@!-]+$`);
const PARAMETER_ARN = new RegExp(`^arn:aws:ssm:${RUNTIME_REGION}:${RUNTIME_ACCOUNT}:parameter/[A-Za-z0-9_./-]+$`);
const S3_OBJECT_ARN = /^arn:aws:s3:::[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]\/[^*]+$/;
const IMAGE = new RegExp(`^${RUNTIME_ACCOUNT}\\.dkr\\.ecr\\.${RUNTIME_REGION}\\.amazonaws\\.com/([a-z0-9][a-z0-9._/-]*)@(sha256:[a-f0-9]{64})$`);
const dependencyId = (value) => crypto.createHash("sha256").update(JSON.stringify({ principalArn: value.principalArn, action: value.action, resource: value.resource, source: value.source, context: value.context || null })).digest("hex");
const add = (dependencies, value) => { const id = dependencyId(value); dependencies.set(id, Object.freeze({ ...value, dependencyId: id })); };

export function parseEcsSecretsManagerReference(value) {
  if (typeof value !== "string") throw new Error("Production ECS Secrets Manager reference is invalid.");
  const fields = value.split(":");
  if (![7, 10].includes(fields.length)) throw new Error("Production ECS Secrets Manager reference is malformed.");
  const resource = fields.slice(0, 7).join(":");
  if (!SECRET_ARN.test(resource)) throw new Error("Production ECS Secrets Manager reference is outside the canonical production scope.");
  const [jsonKey = "", versionStage = "", versionId = ""] = fields.slice(7);
  if ((jsonKey && !/^[^:\s]{1,256}$/.test(jsonKey)) || (versionStage && !/^[A-Za-z0-9/_+=.@-]{1,256}$/.test(versionStage))
    || (versionId && !/^[A-Za-z0-9_-]{32,64}$/.test(versionId)) || (fields.length === 10 && !jsonKey && !versionStage && !versionId)) throw new Error("Production ECS Secrets Manager selector is malformed or ambiguous.");
  return Object.freeze({ resource, jsonKey: jsonKey || null, versionStage: versionStage || null, versionId: versionId || null,
    selectorMode: versionStage && versionId ? "STAGE_AND_VERSION" : versionStage ? "VERSION_STAGE" : versionId ? "VERSION_ID" : "AWSCURRENT" });
}

function referenceDependency(dependencies, valueFrom, principalArn, source) {
  if (typeof valueFrom === "string" && valueFrom.startsWith(`arn:aws:secretsmanager:${RUNTIME_REGION}:${RUNTIME_ACCOUNT}:secret:`)) {
    const selector = parseEcsSecretsManagerReference(valueFrom);
    return add(dependencies, { consumer: "EXECUTION_ROLE", principalArn, action: "secretsmanager:GetSecretValue", resource: selector.resource, source, context: { secretSelector: selector } });
  }
  if (PARAMETER_ARN.test(valueFrom || "")) return add(dependencies, { consumer: "EXECUTION_ROLE", principalArn, action: "ssm:GetParameters", resource: valueFrom, source });
  throw new Error(`Unknown production ECS runtime reference at ${source}.`);
}

export function deriveEcsRuntimeDependencies(candidate) {
  const executionRoleArn = candidate?.executionRoleArn; const taskRoleArn = candidate?.taskRoleArn;
  if (!RUNTIME_ROLE_ARN.test(executionRoleArn || "") || !RUNTIME_ROLE_ARN.test(taskRoleArn || "")) throw new Error("Production ECS candidate roles are missing or outside the production account.");
  const dependencies = new Map(); const definitions = candidate?.containerDefinitions;
  if (!Array.isArray(definitions) || !definitions.length || definitions.some((value) => !value || typeof value !== "object") || new Set(definitions.map(({ name }) => name)).size !== definitions.length || definitions.some(({ name }) => typeof name !== "string" || !name)) throw new Error("Production ECS container identities are missing, invalid, or duplicated.");
  for (const container of definitions) {
    const source = `containerDefinitions[name=${container.name}]`; const image = IMAGE.exec(container.image || "");
    if (!image) throw new Error(`Production ECS image must be an exact production ECR digest at ${source}.image.`);
    const repositoryArn = `arn:aws:ecr:${RUNTIME_REGION}:${RUNTIME_ACCOUNT}:repository/${image[1]}`;
    add(dependencies, { consumer: "EXECUTION_ROLE", principalArn: executionRoleArn, action: "ecr:GetAuthorizationToken", resource: "*", source: `${source}.image` });
    for (const action of ["ecr:BatchCheckLayerAvailability", "ecr:GetDownloadUrlForLayer", "ecr:BatchGetImage"]) add(dependencies, { consumer: "EXECUTION_ROLE", principalArn: executionRoleArn, action, resource: repositoryArn, source: `${source}.image`, context: { repositoryName: image[1], imageDigest: image[2] } });
    for (const [field, values] of [["secrets", container.secrets || []], ["logConfiguration.secretOptions", container.logConfiguration?.secretOptions || []]]) {
      if (!Array.isArray(values) || new Set(values.map(({ name }) => name)).size !== values.length) throw new Error(`Production ECS secret identities are invalid or duplicated at ${source}.${field}.`);
      for (const secret of values) referenceDependency(dependencies, secret?.valueFrom, executionRoleArn, `${source}.${field}[name=${secret?.name || "<missing>"}]`);
    }
    if (container.repositoryCredentials != null) referenceDependency(dependencies, container.repositoryCredentials?.credentialsParameter, executionRoleArn, `${source}.repositoryCredentials`);
    for (const [index, file] of (container.environmentFiles || []).entries()) {
      if (file?.type !== "s3" || !S3_OBJECT_ARN.test(file?.value || "")) throw new Error(`Unknown production ECS environment file at ${source}.environmentFiles[${index}].`);
      add(dependencies, { consumer: "EXECUTION_ROLE", principalArn: executionRoleArn, action: "s3:GetObject", resource: file.value, source: `${source}.environmentFiles[${index}]` });
      add(dependencies, { consumer: "EXECUTION_ROLE", principalArn: executionRoleArn, action: "s3:GetBucketLocation", resource: file.value.slice(0, file.value.indexOf("/")), source: `${source}.environmentFiles[${index}]` });
    }
    const logs = container.logConfiguration;
    if (logs?.logDriver === "awslogs") {
      const group = logs.options?.["awslogs-group"];
      const createGroup = logs.options?.["awslogs-create-group"];
      if (typeof group !== "string" || group.length > 512 || !/^\/[._/#A-Za-z0-9-]+$/.test(group) || logs.options?.["awslogs-region"] !== RUNTIME_REGION
        || (createGroup !== undefined && !["true", "false"].includes(createGroup))) throw new Error(`Production awslogs configuration is not exact at ${source}.logConfiguration.`);
      const groupArn = `arn:aws:logs:${RUNTIME_REGION}:${RUNTIME_ACCOUNT}:log-group:${group}`;
      for (const action of ["logs:CreateLogStream", "logs:PutLogEvents"]) add(dependencies, { consumer: "EXECUTION_ROLE", principalArn: executionRoleArn, action, resource: `${groupArn}:log-stream:*`, source: `${source}.logConfiguration` });
      if (createGroup === "true") add(dependencies, { consumer: "EXECUTION_ROLE", principalArn: executionRoleArn, action: "logs:CreateLogGroup", resource: groupArn, source: `${source}.logConfiguration` });
    } else if (logs?.secretOptions?.length) throw new Error(`Secret log options require a supported production log driver at ${source}.logConfiguration.`);
  }
  for (const [index, volume] of (candidate.volumes || []).entries()) {
    const efs = volume?.efsVolumeConfiguration;
    if (!efs || efs.authorizationConfig?.iam !== "ENABLED") continue;
    if (!/^fs-[a-f0-9]+$/.test(efs.fileSystemId || "")) throw new Error(`Production EFS volume identity is invalid at volumes[${index}].`);
    for (const action of ["elasticfilesystem:ClientMount", "elasticfilesystem:ClientWrite"]) add(dependencies, { consumer: "TASK_ROLE", principalArn: taskRoleArn, action, resource: `arn:aws:elasticfilesystem:${RUNTIME_REGION}:${RUNTIME_ACCOUNT}:file-system/${efs.fileSystemId}`, source: `volumes[${index}].efsVolumeConfiguration` });
  }
  return Object.freeze([...dependencies.values()].sort((left, right) => left.dependencyId.localeCompare(right.dependencyId)));
}
