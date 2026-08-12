import { execFileSync } from "node:child_process";
import { readFreshProtectedMainIdentity } from "./stage-b-deployment-identity.mjs";

const git = (args, run = execFileSync) => String(run("git", args, { encoding: "utf8" })).trim();

export const assertMergedStageBRelease = (releaseSha, { run = execFileSync } = {}) => {
  if (!/^[a-f0-9]{40}$/.test(releaseSha || "")) throw new Error("Stage B release SHA must be a full 40-character commit SHA.");
  const fresh = readFreshProtectedMainIdentity({ run: (args) => run("git", args, { encoding: "utf8" }) });
  git(["cat-file", "-e", `${releaseSha}^{commit}`], run);
  git(["merge-base", "--is-ancestor", releaseSha, fresh.freshRemoteMainSha], run);
  if (fresh.headSha !== releaseSha) throw new Error("Checked-out HEAD does not equal the approved Stage B release SHA.");
};

if (process.argv[1] === new URL(import.meta.url).pathname) assertMergedStageBRelease(process.argv[2]);
