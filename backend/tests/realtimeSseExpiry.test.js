const assert = require("node:assert/strict");
const { closeSseAtTokenExpiry } = require("../dist/utils/realtime");

(async () => {
  const writes = [];
  let ended = false;
  const res = {
    write: (chunk) => { writes.push(String(chunk)); return true; },
    end: () => { ended = true; },
  };
  const cancel = closeSseAtTokenExpiry({ sseTokenExpiresAtMs: Date.now() + 20 }, res, "dashboard");
  await new Promise((resolve) => setTimeout(resolve, 50));
  assert(ended, "authenticated stream must close when its access token expires");
  assert(writes.join("").includes('"type":"session.expired"'), "expiry must give the client a refresh signal");
  assert(!writes.join("").includes("token"), "expiry signal must not contain credentials");
  cancel();
  console.log("realtime SSE expiry tests passed");
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
