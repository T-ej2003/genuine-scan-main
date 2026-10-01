import crypto from "node:crypto";

const encode = (value) => encodeURIComponent(value).replace(/[!'()*]/g, (character) => `%${character.charCodeAt(0).toString(16).toUpperCase()}`);
const hmac = (key, value, encoding) => crypto.createHmac("sha256", key).update(value).digest(encoding);

export function signRdsIamToken({ host, port = 5432, username, region = "eu-west-2", credentials, now = new Date() }) {
  if (!/^[a-z0-9][a-z0-9.-]*\.eu-west-2\.rds\.amazonaws\.com$/.test(host || "") || !Number.isInteger(port) || port !== 5432
      || username !== "mscqr_prod_victoria_recovery" || region !== "eu-west-2"
      || !credentials?.accessKeyId || !credentials?.secretAccessKey || !credentials?.sessionToken) {
    throw new Error("RDS_IAM_BINDING_INVALID");
  }
  const date = now.toISOString().replace(/[:-]|\.\d{3}/g, "");
  const day = date.slice(0, 8);
  const hostHeader = `${host}:${port}`;
  const fields = {
    Action: "connect", DBUser: username, "X-Amz-Algorithm": "AWS4-HMAC-SHA256",
    "X-Amz-Credential": `${credentials.accessKeyId}/${day}/${region}/rds-db/aws4_request`,
    "X-Amz-Date": date, "X-Amz-Expires": "900", "X-Amz-Security-Token": credentials.sessionToken,
    "X-Amz-SignedHeaders": "host",
  };
  const query = Object.keys(fields).sort().map((key) => `${encode(key)}=${encode(fields[key])}`).join("&");
  const canonical = `GET\n/\n${query}\nhost:${hostHeader}\n\nhost\nUNSIGNED-PAYLOAD`;
  const scope = `${day}/${region}/rds-db/aws4_request`;
  const stringToSign = `AWS4-HMAC-SHA256\n${date}\n${scope}\n${crypto.createHash("sha256").update(canonical).digest("hex")}`;
  const dateKey = hmac(`AWS4${credentials.secretAccessKey}`, day);
  const regionKey = hmac(dateKey, region);
  const serviceKey = hmac(regionKey, "rds-db");
  const signingKey = hmac(serviceKey, "aws4_request");
  const signature = hmac(signingKey, stringToSign, "hex");
  return `${hostHeader}/?${query}&X-Amz-Signature=${signature}`;
}

export async function taskRoleCredentials(env = process.env) {
  const relative = env.AWS_CONTAINER_CREDENTIALS_RELATIVE_URI;
  if (!relative || !/^\/[A-Za-z0-9/_-]+$/.test(relative)) throw new Error("TASK_ROLE_CREDENTIALS_UNAVAILABLE");
  const response = await fetch(`http://169.254.170.2${relative}`, { signal: AbortSignal.timeout(3000) });
  if (!response.ok) throw new Error("TASK_ROLE_CREDENTIALS_UNAVAILABLE");
  const value = await response.json();
  if (!value.AccessKeyId || !value.SecretAccessKey || !value.Token) throw new Error("TASK_ROLE_CREDENTIALS_INVALID");
  return { accessKeyId: value.AccessKeyId, secretAccessKey: value.SecretAccessKey, sessionToken: value.Token };
}
