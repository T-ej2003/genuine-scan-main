import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";

const SHA = /^[a-f0-9]{40}$/;
const git = (args, cwd) => execFileSync("git", args, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });

export function readProductionGitChanges(base, target, cwd, run = git) {
  assert.match(base, SHA); assert.match(target, SHA);
  const parse = (args) => {
    const fields = run(["diff", ...args, "--name-status", "-z", `${base}..${target}`], cwd).split("\0").filter(Boolean);
    const changes = [];
    for (let i = 0; i < fields.length;) {
      const status = fields[i++];
      assert.match(status, /^(?:[ACDMRTU]|[RC][0-9]+)$/);
      const count = /^[RC]/.test(status) ? 2 : 1;
      assert.ok(i + count <= fields.length, "Git change record is incomplete");
      changes.push({ status: status[0], paths: fields.slice(i, i + count) }); i += count;
    }
    return changes;
  };
  const structural = parse(["--no-renames"]);
  const paired = parse(["--find-renames", "--find-copies-harder"]);
  return { paths: [...new Set([...structural, ...paired].flatMap((change) => change.paths))], structural, paired };
}
