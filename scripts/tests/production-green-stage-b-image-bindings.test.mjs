import assert from "node:assert/strict";
import test from "node:test";
import { assertStageBImageBindings } from "../aws/stage-b-image-bindings.mjs";

const binding = { service: "backend", releaseSha: "a".repeat(40), sourceContractSha256: "b".repeat(64), migrationSetDigest: "c".repeat(64) };
const labels = { "org.opencontainers.image.revision": binding.releaseSha, "com.mscqr.rls.source-contract-sha256": binding.sourceContractSha256, "com.mscqr.rls.migration-set-digest": binding.migrationSetDigest, "org.opencontainers.image.title": "mscqr-backend" };

test("Stage B reuses only an image built with its exact bindings", () => {
  assert.doesNotThrow(() => assertStageBImageBindings({ ...binding, labels }));
  assert.throws(() => assertStageBImageBindings({ ...binding, labels: { "org.opencontainers.image.revision": binding.releaseSha, "org.opencontainers.image.title": "mscqr-backend" } }), /not bound/);
  for (const candidate of [
    { "com.mscqr.rls.source-contract-sha256": "d".repeat(64) },
    { "com.mscqr.rls.migration-set-digest": "d".repeat(64) },
    { "org.opencontainers.image.revision": "d".repeat(40) },
    { "org.opencontainers.image.title": "mscqr-worker" },
  ]) assert.throws(() => assertStageBImageBindings({ ...binding, labels: { ...labels, ...candidate } }), /not bound/);
});
