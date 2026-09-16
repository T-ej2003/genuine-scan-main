import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import ts from "typescript";
import { literalPath } from "../release/route-literal-path.mjs";

test("query suffixes do not become route segments; dynamic path segments are retained", () => {
  const parse = (text) => {
    const source = ts.createSourceFile("fixture.ts", text, ts.ScriptTarget.Latest, true);
    return literalPath(source.statements[0].expression, source);
  };
  assert.equal(parse('`/qr/batches/${batchId}/allocation-map${licenseeId ? `?licenseeId=${licenseeId}` : ""}`'), "/qr/batches/:batchId/allocation-map");
  assert.equal(parse('`/objects/${id}?limit=${limit}`'), "/objects/:id");
  assert.equal(parse('`/objects/${id}${flag ? "?a=1" : "?b=2"}`'), "/objects/:id");
  assert.notEqual(parse('`/objects/${flag ? "/private" : "/public"}`'), "/objects/");
  assert.equal(parse('`/missing/${id}/route?limit=${limit}`'), "/missing/:id/route");
});

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
    inventory.backendAuthority.reachableFunctions.some(({ source, symbol }) =>
      source === "backend/src/controllers/printerAgentController.ts" && symbol === "reportPrinterHeartbeat")
  );
  assert.equal(
    inventory.backendAuthority.reachableFunctions.some(({ source, symbol }) =>
      source === "backend/src/controllers/printerAgentController.ts" && symbol === "quarantinedLegacyPrinterHeartbeat"),
    false
  );
});

test("reachable authority retains exact structural source and symbol identities", () => {
  const references = inventory.backendAuthority.reachableFunctions;
  for (const reference of references) {
    assert.deepEqual(Object.keys(reference).sort(), ["source", "symbol"]);
    assert.ok(existsSync(path.join(root, reference.source)));
    assert.equal(typeof reference.symbol, "string");
    assert.ok(reference.symbol.length > 0);
  }
  const identities = references.map(({ source, symbol }) => `${source}:${symbol}`);
  assert.equal(new Set(identities).size, identities.length);
  assert.deepEqual(identities, [...identities].sort());
  for (const { source, symbol } of [
    {
      source: "backend/src/controllers/verify/authHandlers.ts",
      symbol: "isAllowedE2eDryRunOtpDelivery",
    },
    {
      source: "backend/src/services/qrTokenService.ts",
      symbol: "hasEd25519QrSigningKeys",
    },
  ]) assert.ok(references.some((reference) => reference.source === source && reference.symbol === symbol));
});

test("removed QR ZIP implementation and vulnerable archive dependency stay absent", () => {
  assert.equal(existsSync(path.join(root, "backend/src/services/qrZipStreamService.ts")), false);
  const packageJson = JSON.parse(readFileSync(path.join(root, "backend/package.json"), "utf8"));
  assert.equal(packageJson.dependencies?.archiver, undefined);
  assert.equal(packageJson.devDependencies?.["@types/archiver"], undefined);
});
