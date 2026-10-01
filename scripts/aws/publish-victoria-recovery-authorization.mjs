import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { createVictoriaRecoveryAuthorization } from "./victoria-recovery-authorization.mjs";
import { assertProductionEnvironmentActualReviewer, assertProductionEnvironmentApprovalEvidence } from "./production-github-environment-approval.mjs";
import { createProductionAwsCommandRunner, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "./production-credential-source-contract.mjs";

const required = (name) => {
  const value = process.env[name];
  if (!value || value.startsWith("--")) throw new Error(`${name}_MISSING`);
  return value;
};

function awsCall(runAws, args, { json = true } = {}) {
  const output = runAws(args);
  return json ? JSON.parse(output) : output.trim();
}

function kmsSign(keyId, runAws) {
  return async ({ message }) => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), "victoria-recovery-sign-"));
    fs.chmodSync(directory, 0o700);
    const file = path.join(directory, "message.bin");
    try {
      fs.writeFileSync(file, message, { mode: 0o600, flag: "wx" });
      const response = awsCall(runAws, ["kms", "sign", "--region", "eu-west-2", "--key-id", keyId, "--message", `fileb://${file}`,
        "--message-type", "RAW", "--signing-algorithm", "RSASSA_PSS_SHA_256"]);
      return Buffer.from(response.Signature, "base64");
    } finally {
      fs.rmSync(directory, { recursive: true, force: true });
    }
  };
}

export async function publishVictoriaRecoveryAuthorization(env = process.env) {
  if (env.GITHUB_REF !== "refs/heads/main" || env.GITHUB_RUN_ATTEMPT !== "1"
      || env.SOURCE_SHA !== env.GITHUB_SHA || !/^[a-f0-9]{40}$/.test(env.SOURCE_SHA || "")) throw new Error("PROTECTED_MAIN_SOURCE_INVALID");
  const approvalPath = required("VICTORIA_RECOVERY_APPROVAL_FILE");
  const approvalEvidence = JSON.parse(fs.readFileSync(approvalPath, "utf8"));
  const workflowRef = "T-ej2003/genuine-scan-main/.github/workflows/execute-victoria-onboarding-recovery.yml@refs/heads/main";
  const approvalOptions = {
    sourceSha: env.SOURCE_SHA, repository: "T-ej2003/genuine-scan-main", environment: "production-victoria-recovery",
    workflowRef, eventName: env.GITHUB_EVENT_NAME, workflowRunId: env.GITHUB_RUN_ID,
    workflowRunAttempt: env.GITHUB_RUN_ATTEMPT, executionActor: env.GITHUB_ACTOR,
    githubActions: env.GITHUB_ACTIONS,
  };
  const runAws = createProductionAwsCommandRunner({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.GITHUB_OIDC_RELEASE_DEPLOYER, env });
  assertProductionEnvironmentApprovalEvidence(approvalEvidence, approvalOptions);
  assertProductionEnvironmentActualReviewer(approvalEvidence, { sourceSha: env.SOURCE_SHA, repository: approvalOptions.repository, executionActor: env.GITHUB_ACTOR });
  const signingKeyArn = required("VICTORIA_RECOVERY_SIGNING_KEY_ARN");
  const bucket = required("VICTORIA_RECOVERY_EVIDENCE_BUCKET");
  const authorization = await createVictoriaRecoveryAuthorization({
    sourceSha: env.SOURCE_SHA,
    executorImage: required("VICTORIA_RECOVERY_IMAGE"),
    executorTaskDefinition: required("VICTORIA_RECOVERY_TASK_DEFINITION"),
    signingKeyArn, approvalEvidence, validateApproval: () => {}, sign: kmsSign(signingKeyArn, runAws),
  });
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "victoria-recovery-authorization-"));
  fs.chmodSync(directory, 0o700);
  const authorizationPath = path.join(directory, "authorization.json");
  const authorizationBytes = Buffer.from(`${JSON.stringify(authorization)}\n`);
  const authorizationHash = crypto.createHash("sha256").update(authorizationBytes).digest("hex");
  try {
    fs.writeFileSync(authorizationPath, authorizationBytes, { mode: 0o600, flag: "wx" });
    runAws(["s3api", "put-object", "--region", "eu-west-2", "--bucket", bucket, "--key", `authorizations/${authorization.nonce}.json`,
      "--body", authorizationPath, "--if-none-match", "*", "--server-side-encryption", "aws:kms"]);
    return Object.freeze({ nonce: authorization.nonce, authorizationKey: `authorizations/${authorization.nonce}.json`, authorizationSha256: authorizationHash });
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
}

if (import.meta.url === pathToFileURL(process.argv[1] || "").href) publishVictoriaRecoveryAuthorization().then((result) => {
  process.stdout.write(`${JSON.stringify(result)}\n`);
}).catch((error) => {
  process.stderr.write(`${/^[A-Z0-9_]+$/.test(error.message) ? error.message : "VICTORIA_RECOVERY_AUTHORIZATION_FAILED"}\n`);
  process.exitCode = 1;
});
