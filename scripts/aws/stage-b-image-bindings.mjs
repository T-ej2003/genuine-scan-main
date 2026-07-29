const titleFor = Object.freeze({ backend: "mscqr-backend", worker: "mscqr-worker", "rls-executor": "mscqr-rls-executor", "rls-canary": "mscqr-rls-canary" });

export const assertStageBImageBindings = ({ labels, service, releaseSha, sourceContractSha256, migrationSetDigest }) => {
  if (!titleFor[service] || !labels || labels["org.opencontainers.image.revision"] !== releaseSha
      || labels["com.mscqr.rls.source-contract-sha256"] !== sourceContractSha256
      || labels["com.mscqr.rls.migration-set-digest"] !== migrationSetDigest
      || labels["org.opencontainers.image.title"] !== titleFor[service]) {
    throw new Error(`Existing ${service} image is not bound to this reviewed Stage B release.`);
  }
};

if (process.argv[1] === new URL(import.meta.url).pathname) {
  const [service, releaseSha, sourceContractSha256, migrationSetDigest] = process.argv.slice(2);
  let labels;
  try { labels = JSON.parse(await new Promise((resolve, reject) => { let input = ""; process.stdin.on("data", (chunk) => { input += chunk; }); process.stdin.on("end", () => resolve(input)); process.stdin.on("error", reject); })); } catch { throw new Error("Existing image labels are not valid JSON."); }
  assertStageBImageBindings({ labels, service, releaseSha, sourceContractSha256, migrationSetDigest });
}
