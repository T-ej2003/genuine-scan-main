// Load this bootstrap only from the protected-main Git object, never from a writable checkout.
import assert from "node:assert/strict";
import fs from "node:fs";
import https from "node:https";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";

const repository = "T-ej2003/genuine-scan-main";
const bootstrapPath = "scripts/aws/production-d15-ledger-readback.mjs";
const ledgerPath = "scripts/aws/production-d15-ledger-runtime.mjs";
const sourcePaths = Object.freeze(["scripts/aws", "infra/aws/terraform/lambda/production-rls-approval-broker/ecs-task-definition-readback.mjs"]);
const gitEnvironment = Object.freeze({ HOME: "/nonexistent", PATH: "/usr/bin:/bin", LANG: "C", LC_ALL: "C",
  GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_GLOBAL: "/dev/null", GIT_NO_REPLACE_OBJECTS: "1" });

export function assertTrustedBootstrapExecutable(file, fsOps = fs) {
  assert.ok(file === "/usr/bin/git" || file === "/usr/bin/tar", "Bootstrap executable is outside its fixed command set");
  const resolved = fsOps.realpathSync(file);
  const stat = fsOps.statSync(resolved);
  assert.ok(file === "/usr/bin/git" ? resolved === "/usr/bin/git" : ["/usr/bin/tar", "/usr/bin/bsdtar"].includes(resolved));
  assert.ok(stat.isFile() && stat.uid === 0 && (stat.mode & 0o111) && !(stat.mode & 0o022), `Unsafe bootstrap executable: ${file}`);
  return resolved;
}

export function assertProtectedMainBranch(branch) {
  assert.equal(branch?.name, "main");
  assert.equal(branch._links?.self, `https://api.github.com/repos/${repository}/branches/main`);
  const sha = branch.commit?.sha;
  assert.match(sha || "", /^[a-f0-9]{40}$/);
  assert.equal(branch.commit.url, `https://api.github.com/repos/${repository}/commits/${sha}`);
  return sha;
}

export function fetchProtectedMain() {
  return new Promise((resolve, reject) => {
    const request = https.get({ hostname: "api.github.com", path: `/repos/${repository}/branches/main`,
      headers: { "User-Agent": "mscqr-d15-ledger-bootstrap", Accept: "application/vnd.github+json" }, timeout: 15000 }, (response) => {
      if (response.statusCode !== 200) { response.resume(); reject(new Error(`Protected main API returned ${response.statusCode}`)); return; }
      let body = "";
      response.setEncoding("utf8");
      response.on("data", (chunk) => { body += chunk; if (body.length > 1024 * 1024) request.destroy(new Error("Protected main response is oversized")); });
      response.on("end", () => { try { resolve(JSON.parse(body)); } catch (error) { reject(error); } });
      response.on("error", reject);
    });
    request.on("timeout", () => request.destroy(new Error("Protected main API timed out")));
    request.on("error", reject);
  });
}

export async function runD15LedgerBootstrap({ toolingSha, sourceRepository, mode, args = [], readMain = fetchProtectedMain,
  load = (file) => import(pathToFileURL(file).href), beforeLoad = () => {} }) {
  assert.match(toolingSha || "", /^[a-f0-9]{40}$/);
  assert.ok(["authorize", "run", "recover", "verify"].includes(mode));
  assert.equal(args.length, mode === "authorize" ? 1 : 2);
  assert.ok(path.isAbsolute(sourceRepository) && fs.realpathSync(sourceRepository) === sourceRepository);
  assert.ok(args.every((arg) => typeof arg === "string" && path.isAbsolute(arg)));
  const currentMain = assertProtectedMainBranch(await readMain());
  if (mode === "authorize" || mode === "run") assert.equal(toolingSha, currentMain, "Execution requires exact protected main");
  const gitExecutable = assertTrustedBootstrapExecutable("/usr/bin/git");
  const tarExecutable = assertTrustedBootstrapExecutable("/usr/bin/tar");
  const git = (cwd, argv, options = {}) => execFileSync(gitExecutable, ["-C", cwd, "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", ...argv],
    { env: gitEnvironment, encoding: "utf8", maxBuffer: 16 * 1024 * 1024, stdio: ["ignore", "pipe", "pipe"], ...options });
  const originalRoot = git(sourceRepository, ["rev-parse", "--show-toplevel"]).trim();
  assert.equal(fs.realpathSync(originalRoot), sourceRepository);
  assert.equal(git(sourceRepository, ["cat-file", "-t", toolingSha]).trim(), "commit");
  git(sourceRepository, ["merge-base", "--is-ancestor", toolingSha, currentMain]);
  const authenticatedBootstrap = git(sourceRepository, ["show", `${toolingSha}:${bootstrapPath}`], { encoding: null });
  assert.ok(fs.readFileSync(fileURLToPath(import.meta.url)).equals(authenticatedBootstrap), "Bootstrap differs from authenticated Git source");
  const tree = git(sourceRepository, ["ls-tree", "-r", "-z", toolingSha, "--", ...sourcePaths]).split("\0").filter(Boolean);
  assert.ok(tree.length > 0 && tree.every((entry) => {
    const match = /^(?:100644|100755) blob [a-f0-9]{40}\t(.+)$/.exec(entry);
    return match && sourcePaths.some((prefix) => match[1] === prefix || match[1].startsWith(`${prefix}/`))
      && match[1].split("/").every((segment) => segment && ![".", "..", ".git"].includes(segment));
  }), "Source tree contains a symlink or unsafe entry");
  const objectPath = git(sourceRepository, ["rev-parse", "--git-path", "objects"]).trim();
  const objects = fs.realpathSync(path.isAbsolute(objectPath) ? objectPath : path.resolve(sourceRepository, objectPath));
  const copy = fs.mkdtempSync("/tmp/mscqr-d15-ledger-source-");
  const originalCwd = process.cwd();
  fs.chmodSync(copy, 0o700);
  try {
    const archive = path.join(copy, "source.tar");
    git(sourceRepository, ["archive", "--format=tar", `--output=${archive}`, toolingSha, ...sourcePaths]);
    assert.ok(fs.statSync(archive).size <= 32 * 1024 * 1024, "Authenticated source archive exceeds the fixed dependency scope");
    execFileSync(tarExecutable, ["-xf", archive, "-C", copy], { env: { PATH: "/usr/bin:/bin", LANG: "C", LC_ALL: "C" }, stdio: "ignore" });
    fs.unlinkSync(archive);
    git(copy, ["init", "--quiet"]);
    fs.mkdirSync(path.join(copy, ".git/objects/info"), { recursive: true });
    fs.writeFileSync(path.join(copy, ".git/objects/info/alternates"), `${objects}\n`, { mode: 0o600 });
    git(copy, ["update-ref", "refs/heads/main", toolingSha]);
    git(copy, ["symbolic-ref", "HEAD", "refs/heads/main"]);
    git(copy, ["read-tree", toolingSha]);
    beforeLoad(copy);
    assert.equal(git(copy, ["status", "--porcelain=v1", "--untracked-files=all", "--", ...sourcePaths]).trim(), "", "Authenticated source copy changed");
    assert.ok(fs.readFileSync(path.join(copy, bootstrapPath)).equals(authenticatedBootstrap), "Bootstrap source copy changed");
    const ledger = path.join(copy, ledgerPath);
    assert.ok(fs.statSync(ledger).isFile() && !fs.lstatSync(ledger).isSymbolicLink());
    process.chdir(copy);
    const { runD15LedgerReadback } = await load(ledger);
    assert.equal(typeof runD15LedgerReadback, "function");
    return await runD15LedgerReadback(mode, ...args);
  } finally { process.chdir(originalCwd); fs.rmSync(copy, { recursive: true, force: true }); }
}

if (process.argv[1] && fs.realpathSync(process.argv[1]) === fs.realpathSync(fileURLToPath(import.meta.url))) {
  try {
    assert.ok(process.argv.length === 6 || process.argv.length === 7);
    const [, , toolingSha, sourceRepository, mode, ...args] = process.argv;
    console.log(JSON.stringify(await runD15LedgerBootstrap({ toolingSha, sourceRepository, mode, args })));
  } catch (error) {
    console.error(`D15 trusted bootstrap failed closed: ${error.message}`);
    process.exitCode = 1;
  }
}
