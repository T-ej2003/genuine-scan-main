const assert = require("node:assert/strict");

const repository = require("../dist/rls-waves/session-b/b03/repositoryFunctions");
const boundary = require("../dist/rls-waves/session-b/b03/systemContext");
const mail = require("../dist/services/supportIntakeMailService");

const original = {
  claim: repository.claimSupportResponseEmails,
  complete: repository.completeSupportResponseEmail,
  context: boundary.withB03SupportEmailWorkerContext,
  send: mail.sendSupportIssueReply,
};

(async () => {
  let sends = 0;
  let claims = 0;
  const completions = [];
  boundary.withB03SupportEmailWorkerContext = (context, callback) => callback({ requestId: context.requestId });
  repository.claimSupportResponseEmails = async (db, input) => {
    assert.equal(input.batchSize, 1, "the worker must claim only the email it can send next");
    assert.equal(sends, claims, "email must not be sent before a committed claim");
    claims += 1;
    if (claims > 2) return [];
    return [{
      id: "00000000-0000-4202-8100-000000000011", organizationId: null,
      licenseeId: null, body: "A support response", data: {
        claimToken: db.requestId, recipient: "synthetic@example.test", subject: "Support",
      },
    }];
  };
  repository.completeSupportResponseEmail = async (_db, result) => {
    completions.push(result);
    assert.equal(sends, completions.length);
  };
  mail.sendSupportIssueReply = async () => {
    sends += 1;
    return sends === 1
      ? { delivered: false, attempted: false, errorCode: "SMTP_CONFIG_MISSING" }
      : { delivered: true, attempted: true, providerMessageId: "synthetic-provider-id" };
  };
  const { flushSupportResponseEmailOutbox } = require("../dist/services/supportResponseEmailOutboxService");
  await flushSupportResponseEmailOutbox();
  await flushSupportResponseEmailOutbox();
  await flushSupportResponseEmailOutbox();
  assert.deepEqual(completions.map((row) => row.status), ["FAILED", "SENT"]);
  assert.equal(sends, 2);
  console.log("support response email outbox worker passed");
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
}).finally(() => {
  repository.claimSupportResponseEmails = original.claim;
  repository.completeSupportResponseEmail = original.complete;
  boundary.withB03SupportEmailWorkerContext = original.context;
  mail.sendSupportIssueReply = original.send;
});
