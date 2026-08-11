import assert from "node:assert/strict";
import test from "node:test";
import { executeProductionRotationInventory } from "../security/production-rotation-state-inventory.mjs";

const fixtureUrl = process.env.MSCQR_ROTATION_INVENTORY_FIXTURE_DATABASE_URL;

test("production-shaped rotation inventory SQL parses and executes in PostgreSQL", { skip: !fixtureUrl }, () => {
  const inventory = executeProductionRotationInventory({
    env: { ...process.env, DATABASE_URL: fixtureUrl, ROTATION_INVENTORY_APPROVED: "true", ROTATION_INVENTORY_RLS_ROLE: "mscqr_prod_rls" },
  });
  for (const category of ["qrArtifacts", "artifactRecords", "legacyComplianceArtifacts"]) assert.ok(category in inventory);
  assert.equal(typeof inventory.qrArtifacts.count, "number");
  assert.equal(typeof inventory.artifactRecords.count, "number");
});
