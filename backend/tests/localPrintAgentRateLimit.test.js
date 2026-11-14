const assert = require("node:assert/strict");
const { spawn, spawnSync } = require("node:child_process");
const { once } = require("node:events");
const fs = require("node:fs/promises");
const net = require("node:net");
const os = require("node:os");
const path = require("node:path");
const { test } = require("node:test");

const connector = path.resolve(__dirname, "../dist/local-print-agent/index.js");

test("local connector limits POST requests by socket address without trusting headers", async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "mscqr-origin-limit-"));
  const portProbe = net.createServer();
  portProbe.listen(0, "127.0.0.1");
  await once(portProbe, "listening");
  const port = portProbe.address().port;
  await new Promise((resolve) => portProbe.close(resolve));
  const env = {
    ...process.env,
    PRINT_AGENT_HOST: "127.0.0.1",
    PRINT_AGENT_PORT: String(port),
    PRINT_AGENT_STATE_FILE: path.join(root, "state.json"),
    PRINT_AGENT_LOCK_DIR: path.join(root, "lock"),
    PRINT_AGENT_BACKEND_URL: "",
    PRINT_GATEWAY_BACKEND_URL: "",
  };
  let child;
  try {
    const initialized = spawnSync(process.execPath, [connector, "--initialize-state"], { env, encoding: "utf8", timeout: 10_000 });
    assert.equal(initialized.status, 0, "Disposable connector identity must initialize");
    child = spawn(process.execPath, [connector], { env, stdio: ["ignore", "pipe", "pipe"] });
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("Connector did not start")), 10_000);
      child.stdout.on("data", (chunk) => {
        if (String(chunk).includes("local print agent listening")) { clearTimeout(timer); resolve(); }
      });
      child.once("exit", (code) => { clearTimeout(timer); reject(new Error(`Connector exited before listening: ${code}`)); });
    });

    const post = (origin, forwardedFor) => fetch(`http://127.0.0.1:${port}/wake`, {
      method: "POST",
      headers: { ...(origin ? { origin } : {}), "x-forwarded-for": forwardedFor, "content-type": "application/json" },
      body: "{}",
    });
    for (let i = 0; i < 35; i++) {
      assert.equal((await post("https://www.mscqr.com", `198.51.100.${i}`)).status, 200,
        "Ordinary authorized connector traffic must remain available");
    }
    assert.equal((await post(undefined, "192.0.2.3")).status, 200,
      "Native connector requests without a browser Origin must remain available");
    for (let i = 0; i < 84; i++) {
      assert.equal((await post("https://untrusted.example", `203.0.113.${i}`)).status, 403,
        "Unauthorized Origin must be denied before the limit is exhausted");
    }
    const blocked = await post("https://www.mscqr.com", "192.0.2.1");
    assert.equal(blocked.status, 429, "Spoofed allowed Origin and forwarded headers must not evade the limit");
    assert.equal(blocked.headers.get("retry-after"), "60");
    assert.match((await blocked.json()).error, /retry in one minute/i);
  } finally {
    if (child && child.exitCode === null) {
      child.kill("SIGTERM");
      await once(child, "exit");
    }
    await fs.rm(root, { recursive: true, force: true });
  }
});
