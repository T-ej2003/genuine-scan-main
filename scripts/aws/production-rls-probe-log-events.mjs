import assert from "node:assert/strict";

export function collectCompleteRlsProbeLogEvents(pages, { maxPages = 100 } = {}) {
  assert.ok(Array.isArray(pages) && pages.length > 0 && pages.length <= maxPages, "Incomplete RLS probe log pagination"); const events = []; let expectedToken;
  for (let index = 0; index < pages.length; index++) { const page = pages[index]; assert.ok(page && Array.isArray(page.events) && page.events.length <= 10000); if (index > 0) assert.equal(page.requestToken, expectedToken); events.push(...page.events); expectedToken = page.nextForwardToken; assert.ok(expectedToken === undefined || typeof expectedToken === "string"); }
  assert.equal(pages.at(-1).nextForwardToken, pages.at(-1).requestToken, "Incomplete RLS probe log pagination"); assert.ok(events.length <= 66, "Unbounded RLS probe output");
  return events.map(({ message }) => { assert.ok(typeof message === "string" && Buffer.byteLength(message) <= 256 * 1024); return message; });
}
