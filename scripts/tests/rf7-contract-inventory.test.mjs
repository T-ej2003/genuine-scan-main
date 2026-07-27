import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";

const root = path.resolve(new URL("../..", import.meta.url).pathname);
const inventory = JSON.parse(
  readFileSync(path.join(root, "documents/security/rls-program/release-fix-7-contract-inventory.json"), "utf8")
);

test("inventory reconciles every finite frontend HTTP consumer", () => {
  assert.equal(inventory.summary.missingFrontendRoutes, 0);
  assert.equal(inventory.backendRoutes.length, inventory.summary.routes);
  assert.equal(inventory.frontendConsumers.length, inventory.summary.frontendConsumers);
});

test("runtime reachability does not activate quarantined function bodies", () => {
  assert.ok(
    inventory.backendAuthority.reachableFunctions.includes(
      "backend/src/controllers/printerAgentController.ts:reportPrinterHeartbeat"
    )
  );
  assert.equal(
    inventory.backendAuthority.reachableFunctions.includes(
      "backend/src/controllers/printerAgentController.ts:quarantinedLegacyPrinterHeartbeat"
    ),
    false
  );
});

test("removed QR ZIP implementation and vulnerable archive dependency stay absent", () => {
  assert.equal(existsSync(path.join(root, "backend/src/services/qrZipStreamService.ts")), false);
  const packageJson = JSON.parse(readFileSync(path.join(root, "backend/package.json"), "utf8"));
  assert.equal(packageJson.dependencies?.archiver, undefined);
  assert.equal(packageJson.devDependencies?.["@types/archiver"], undefined);
});
