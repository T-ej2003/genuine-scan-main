import fs from "node:fs";

export const backendRecoverySecretArn = (name) => `${["arn", "aws", "secretsmanager", "eu-west-2", "368992683803", "secret"].join(":")}:mscqr/prod/${name}-AbCd12`;

export function loadBackendRecoveryTaskDefinition() {
  const task = JSON.parse(fs.readFileSync(new URL("./mscqr-backend-47.task-definition.json", import.meta.url)));
  const secrets = task.taskDefinition.containerDefinitions.find(({ name }) => name === "backend").secrets;
  secrets.find(({ name }) => name === "QR_SIGN_PRIVATE_KEY").valueFrom = backendRecoverySecretArn("qr_sign_private_key");
  secrets.find(({ name }) => name === "QR_SIGN_PUBLIC_KEY").valueFrom = backendRecoverySecretArn("qr_sign_public_key");
  return task;
}
