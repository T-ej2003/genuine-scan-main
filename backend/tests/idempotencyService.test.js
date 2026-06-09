const assert = require("assert");
const prisma = require("../dist/config/database").default;
const {
  beginIdempotentAction,
  completeIdempotentAction,
} = require("../dist/services/idempotencyService");

const run = async () => {
  const store = new Map();
  const backup = {
    findUnique: prisma.actionIdempotencyKey.findUnique,
    deleteMany: prisma.actionIdempotencyKey.deleteMany,
    create: prisma.actionIdempotencyKey.create,
    updateMany: prisma.actionIdempotencyKey.updateMany,
  };

  prisma.actionIdempotencyKey.findUnique = async ({ where }) => store.get(where.keyHash) || null;
  prisma.actionIdempotencyKey.deleteMany = async ({ where }) => {
    store.delete(where.keyHash);
    return { count: 1 };
  };
  prisma.actionIdempotencyKey.create = async ({ data }) => {
    if (store.has(data.keyHash)) {
      const error = new Error("Unique constraint failed");
      error.code = "P2002";
      throw error;
    }
    store.set(data.keyHash, {
      ...data,
      completedAt: null,
      statusCode: null,
      responsePayload: null,
    });
    return store.get(data.keyHash);
  };
  prisma.actionIdempotencyKey.updateMany = async ({ where, data }) => {
    const row = store.get(where.keyHash);
    if (!row || row.completedAt !== null) return { count: 0 };
    store.set(where.keyHash, { ...row, ...data });
    return { count: 1 };
  };

  try {
    const first = await beginIdempotentAction({
      action: "print_job_create",
      scope: "tenant:tenant-a:user:user-a:batch:batch-a",
      idempotencyKey: "operator-click-1",
      requestPayload: { batchId: "batch-a", printerId: "printer-a", quantity: 1 },
      required: true,
    });
    assert.strictEqual(first.replayed, false, "first request should reserve the idempotency key");

    await completeIdempotentAction({
      keyHash: first.keyHash,
      statusCode: 201,
      responsePayload: { success: true, data: { printJobId: "job-a" } },
    });

    const replay = await beginIdempotentAction({
      action: "print_job_create",
      scope: "tenant:tenant-a:user:user-a:batch:batch-a",
      idempotencyKey: "operator-click-1",
      requestPayload: { batchId: "batch-a", printerId: "printer-a", quantity: 1 },
      required: true,
    });
    assert.strictEqual(replay.replayed, true, "same scoped key should replay");
    assert.strictEqual(replay.responsePayload.data.printJobId, "job-a", "replay should return the original print job");

    const crossTenant = await beginIdempotentAction({
      action: "print_job_create",
      scope: "tenant:tenant-b:user:user-b:batch:batch-b",
      idempotencyKey: "operator-click-1",
      requestPayload: { batchId: "batch-b", printerId: "printer-b", quantity: 1 },
      required: true,
    });
    assert.strictEqual(crossTenant.replayed, false, "same key in another tenant/user scope must not replay tenant A data");
    assert.notStrictEqual(crossTenant.keyHash, first.keyHash, "tenant/user scope should change the stored key hash");

    let mismatchBlocked = false;
    try {
      await beginIdempotentAction({
        action: "print_job_create",
        scope: "tenant:tenant-a:user:user-a:batch:batch-a",
        idempotencyKey: "operator-click-1",
        requestPayload: { batchId: "batch-a", printerId: "printer-a", quantity: 2 },
        required: true,
      });
    } catch (error) {
      mismatchBlocked = String(error.message).includes("IDEMPOTENCY_KEY_PAYLOAD_MISMATCH");
    }
    assert.strictEqual(mismatchBlocked, true, "same scoped key with different payload should be rejected");

    console.log("idempotency service tests passed");
  } finally {
    prisma.actionIdempotencyKey.findUnique = backup.findUnique;
    prisma.actionIdempotencyKey.deleteMany = backup.deleteMany;
    prisma.actionIdempotencyKey.create = backup.create;
    prisma.actionIdempotencyKey.updateMany = backup.updateMany;
  }
};

run().catch((error) => {
  console.error(error);
  process.exit(1);
});
