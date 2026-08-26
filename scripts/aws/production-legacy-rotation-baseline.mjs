const ACCOUNT = "368992683803";
const REGION = "eu-west-2";
const SECRET_ARN = new RegExp(`^arn:aws:secretsmanager:${REGION}:${ACCOUNT}:secret:[A-Za-z0-9/_+=.@-]+$`);
const VERSION = /^[A-Za-z0-9._:-]{1,128}$/;

const backendContainer = (taskDefinition) => {
  const container = (taskDefinition?.taskDefinition || taskDefinition)?.containerDefinitions?.find(({ name }) => name === "backend");
  if (!container) throw new Error("Live task definition does not contain the reviewed backend container.");
  return container;
};

export function deriveLegacyRotationBaseline(taskDefinition) {
  const container = backendContainer(taskDefinition);
  const environment = Object.fromEntries((container.environment || []).map(({ name, value }) => [name, value]));
  const baseline = {
    jwtCurrent: container.secrets?.find(({ name }) => name === "JWT_SECRET")?.valueFrom,
    qrPrivateCurrent: container.secrets?.find(({ name }) => name === "QR_SIGN_PRIVATE_KEY")?.valueFrom,
    qrPublicCurrent: container.secrets?.find(({ name }) => name === "QR_SIGN_PUBLIC_KEY")?.valueFrom,
    qrCurrentVersion: environment.QR_SIGN_ACTIVE_KEY_VERSION,
  };
  for (const [name, value] of Object.entries(baseline)) {
    if (name === "qrCurrentVersion") {
      if (!VERSION.test(String(value || ""))) throw new Error("Live QR active key version is invalid.");
    } else if (!SECRET_ARN.test(String(value || ""))) {
      throw new Error(`Live legacy ${name} binding is invalid.`);
    }
  }
  if (new Set([baseline.jwtCurrent, baseline.qrPrivateCurrent, baseline.qrPublicCurrent]).size !== 3) throw new Error("Live legacy signing bindings must be distinct.");
  return Object.freeze(baseline);
}

export function assertBindingsMatchLegacyBaseline(bindings, baseline) {
  if (!bindings || bindings.legacy?.jwtCurrent !== baseline.jwtCurrent || bindings.legacy?.qrPrivateCurrent !== baseline.qrPrivateCurrent || bindings.legacy?.qrPublicCurrent !== baseline.qrPublicCurrent || bindings.legacy?.qrCurrentVersion !== baseline.qrCurrentVersion || bindings.jwt?.currentSecretId !== baseline.jwtCurrent || bindings.qr?.privateCurrentSecretId !== baseline.qrPrivateCurrent || bindings.qr?.publicCurrentSecretId !== baseline.qrPublicCurrent || bindings.qr?.previousKeyVersion !== baseline.qrCurrentVersion) throw new Error("Rotation bindings do not match the authenticated live legacy task-definition bindings.");
  return true;
}
