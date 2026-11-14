const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const vm = require("node:vm");
const { execFileSync } = require("node:child_process");
const { pathToFileURL } = require("node:url");

(async () => {
  const packaging = path.resolve(__dirname, "../local-print-agent/packaging");
  const { normalizeWebAppBaseUrl } = await import(pathToFileURL(path.join(packaging, "web-app-origin.mjs")));
  assert.deepEqual(normalizeWebAppBaseUrl("https://staging.mscqr.example/printer-diagnostics/").origin, "https://staging.mscqr.example");
  assert.equal(normalizeWebAppBaseUrl("https://dr.mscqr.example").origin, "https://dr.mscqr.example");
  const credentialed = new URL("https://staging.mscqr.example");
  credentialed.username = "fixture";
  credentialed.password = "invalid";
  for (const value of ["*", "https://*.mscqr.example", credentialed.href, "https://staging.mscqr.example?x=1", "https://staging.mscqr.example#x", "https://staging.mscqr.example%0a", "http://staging.mscqr.example", "https://staging.mscqr.example&whoami"]) {
    assert.throws(() => normalizeWebAppBaseUrl(value), `${value} must be rejected before packaging`);
  }

  const source = fs.readFileSync(path.join(packaging, "build-connector-release.mjs"), "utf8");
  const renderSource = source.match(/const renderMacWrapper = \(\) => `[\s\S]*?\n`;(?=\n\nconst renderMacPlist)/);
  assert(renderSource, "Mac package wrapper renderer must be present");
  const context = { version: "synthetic", webAppOrigin: "https://staging.mscqr.example" };
  vm.runInNewContext(`${renderSource[0]}\nglobalThis.render = renderMacWrapper;`, context);
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-origin-package-"));
  try {
    const home = path.join(root, "home");
    const stubBin = path.join(root, "stubs");
    const agentBin = path.join(root, "bin");
    fs.mkdirSync(path.join(home, ".mscqr/local-print-agent"), { recursive: true });
    fs.mkdirSync(stubBin);
    fs.mkdirSync(agentBin);
    fs.writeFileSync(path.join(home, ".mscqr/local-print-agent/agent.env"), "PRINT_AGENT_WEB_APP_ORIGIN=https://untrusted.example\nPRINT_AGENT_ALLOWED_ORIGINS=https://dr.mscqr.example\n");
    fs.writeFileSync(path.join(stubBin, "dscl"), `#!/bin/sh\nprintf 'NFSHomeDirectory: %s\\n' '${home}'\n`, { mode: 0o755 });
    const fixture = "#!/bin/sh\nprintf 'origin=%s\\nadditional=%s\\n' \"$PRINT_AGENT_WEB_APP_ORIGIN\" \"$PRINT_AGENT_ALLOWED_ORIGINS\"\n";
    for (const arch of ["arm64", "x64"]) fs.writeFileSync(path.join(agentBin, `mscqr-local-print-agent-${arch}`), fixture, { mode: 0o755 });
    const wrapper = path.join(root, "start-local-print-agent.sh");
    fs.writeFileSync(wrapper, context.render().replace('/usr/local/libexec/mscqr-connector/bin', agentBin), { mode: 0o755 });
    for (let restart = 0; restart < 2; restart++) {
      execFileSync("sh", [wrapper], { env: { ...process.env, HOME: home, PATH: `${stubBin}:${process.env.PATH}` } });
    }
    const log = fs.readFileSync(path.join(home, ".mscqr/local-print-agent/logs/agent.log"), "utf8");
    assert.equal((log.match(/^origin=https:\/\/staging\.mscqr\.example$/gm) || []).length, 2,
      "Packaged origin must override the editable environment file after restart");
    assert.match(log, /^additional=https:\/\/dr\.mscqr\.example$/m, "Explicit additional origins must be preserved");
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
  console.log("Connector web-app origin packaging tests passed");
})().catch((error) => { console.error(error); process.exitCode = 1; });
