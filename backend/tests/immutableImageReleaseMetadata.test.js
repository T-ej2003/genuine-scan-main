const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");
const { test } = require("node:test");
const path = require("node:path");
const { readFileSync } = require("node:fs");

test("Docker build records only exact commit identities and keeps CI placeholder builds usable", () => {
  const dockerfile = readFileSync(path.resolve(__dirname, "../Dockerfile"), "utf8");
  const command = dockerfile.split("\n").find((line) => line.startsWith("RUN node -e '") && line.includes("image-source.json"));
  assert(command);
  const script = command.slice("RUN node -e '".length, -1);
  for (const source of ["a".repeat(40), "ci-local", "unknown", "malformed"]) {
    const child = spawnSync(process.execPath, ["-e", `
      require('node:fs').writeFileSync = (file, value, options) => {
        require('node:assert/strict').equal(file, '/app/image-source.json');
        require('node:assert/strict').equal(options.mode, 0o444);
        process.stdout.write(value);
      };
      ${script}
    `], { encoding: "utf8", env: { ...process.env, RELEASE_GIT_SHA: source } });
    assert.equal(child.status, 0, child.stderr);
    assert.equal(JSON.parse(child.stdout).gitSha, source === "a".repeat(40) ? source : "unknown");
  }
});

test("production image source cannot be overridden by stale task environment", () => {
  const modulePath = require.resolve("../dist/observability/release");
  for (const metadata of [{ gitSha: "a".repeat(40) }, { gitSha: "malformed" }, null]) {
    const child = spawnSync(process.execPath, ["-e", `
      const fs = require('node:fs');
      const original = fs.readFileSync;
      fs.readFileSync = function(file, ...args) {
        if (String(file).endsWith('/image-source.json')) {
          const fixture = ${JSON.stringify(metadata)};
          if (fixture === null) throw new Error('not present');
          return JSON.stringify(fixture);
        }
        return original.call(this, file, ...args);
      };
      process.stdout.write(JSON.stringify(require(${JSON.stringify(modulePath)}).releaseMetadata));
    `], {
      cwd: path.resolve(__dirname, ".."), encoding: "utf8",
      env: { ...process.env, NODE_ENV: "production", RELEASE_GIT_SHA: "b".repeat(40) },
    });
    assert.equal(child.status, 0, child.stderr);
    const result = JSON.parse(child.stdout);
    assert.equal(result.gitSha, metadata?.gitSha === "a".repeat(40) ? metadata.gitSha : "unknown");
    assert.equal(result.imageGitSha, result.gitSha);
    assert.equal(result.deploymentGitSha, "b".repeat(40));
  }
});
