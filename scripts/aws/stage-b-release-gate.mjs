import { execFileSync } from "node:child_process";

const git = (args, run = execFileSync) => String(run("git", args, { encoding: "utf8" })).trim();

export const assertMergedStageBRelease = (releaseSha, { run = execFileSync } = {}) => {
  if (!/^[a-f0-9]{40}$/.test(releaseSha || "")) throw new Error("Stage B release SHA must be a full 40-character commit SHA.");
  git(["fetch", "--no-tags", "origin", "main"], run);
  git(["cat-file", "-e", `${releaseSha}^{commit}`], run);
  git(["merge-base", "--is-ancestor", releaseSha, "origin/main"], run);
  if (git(["rev-parse", "HEAD"], run) !== releaseSha) throw new Error("Checked-out HEAD does not equal the approved Stage B release SHA.");
};

if (process.argv[1] === new URL(import.meta.url).pathname) assertMergedStageBRelease(process.argv[2]);
