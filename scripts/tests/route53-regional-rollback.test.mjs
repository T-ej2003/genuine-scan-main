import assert from "node:assert/strict";
import test from "node:test";

import {
  buildRegionalRollbackPlan,
  DEFAULT_REGIONAL_DNS_POLICY,
  route53BatchChangedSetIdentifiers,
  validateApprovedRegionalRollbackBatch,
} from "../lib/route53-regional-rollback-core.mjs";

test("rollback Europe plan deletes only europe-london and preserves Africa/default", () => {
  const plan = buildRegionalRollbackPlan({
    operation: "rollback-europe",
    policy: DEFAULT_REGIONAL_DNS_POLICY,
  });

  assert.deepEqual(route53BatchChangedSetIdentifiers(plan.cutoverBatch), ["europe-london"]);
  assert.equal(plan.cutoverBatch.Changes[0].Action, "DELETE");
  assert.equal(plan.cutoverBatch.Changes[0].ResourceRecordSet.GeoLocation.ContinentCode, "EU");
  assert.doesNotMatch(JSON.stringify(plan.cutoverBatch), /africa-capetown|default-mumbai/);
});

test("rollback Africa plan deletes only africa-capetown and preserves Europe/default", () => {
  const plan = buildRegionalRollbackPlan({
    operation: "rollback-africa",
    policy: DEFAULT_REGIONAL_DNS_POLICY,
  });

  assert.deepEqual(route53BatchChangedSetIdentifiers(plan.cutoverBatch), ["africa-capetown"]);
  assert.equal(plan.cutoverBatch.Changes[0].Action, "DELETE");
  assert.equal(plan.cutoverBatch.Changes[0].ResourceRecordSet.GeoLocation.ContinentCode, "AF");
  assert.doesNotMatch(JSON.stringify(plan.cutoverBatch), /europe-london|default-mumbai/);
});

test("restore default Mumbai touches only default-mumbai", () => {
  const plan = buildRegionalRollbackPlan({
    operation: "restore-default-mumbai",
    policy: DEFAULT_REGIONAL_DNS_POLICY,
  });

  assert.deepEqual(route53BatchChangedSetIdentifiers(plan.cutoverBatch), ["default-mumbai"]);
  assert.equal(plan.cutoverBatch.Changes[0].Action, "UPSERT");
  assert.equal(plan.cutoverBatch.Changes[0].ResourceRecordSet.GeoLocation.CountryCode, "*");
  assert.doesNotMatch(JSON.stringify(plan.cutoverBatch), /africa-capetown|europe-london/);
});

test("approved apply validation fails without manual approval env var", () => {
  const plan = buildRegionalRollbackPlan({
    operation: "rollback-europe",
    policy: DEFAULT_REGIONAL_DNS_POLICY,
  });

  const findings = validateApprovedRegionalRollbackBatch(plan.cutoverBatch, {
    env: {},
  });

  assert.match(findings.join("\n"), /APPROVED_ROUTE53_ROLLBACK=true/);
});

test("approved apply validation rejects deletion of protected non-A records", () => {
  const findings = validateApprovedRegionalRollbackBatch(
    {
      Changes: [
        {
          Action: "DELETE",
          ResourceRecordSet: {
            Name: "mscqr.com.",
            Type: "MX",
            TTL: 300,
            ResourceRecords: [{ Value: "10 mx1.privateemail.com" }],
          },
        },
        {
          Action: "DELETE",
          ResourceRecordSet: {
            Name: "www.mscqr.com.",
            Type: "CNAME",
            TTL: 300,
            ResourceRecords: [{ Value: "mscqr.com" }],
          },
        },
      ],
    },
    { env: { APPROVED_ROUTE53_ROLLBACK: "true" } },
  );

  assert.match(findings.join("\n"), /protected MX record/);
  assert.match(findings.join("\n"), /protected CNAME record/);
  assert.match(findings.join("\n"), /geolocation A record/);
});

test("approved apply validation accepts generated geolocation A rollback batch with approval", () => {
  const plan = buildRegionalRollbackPlan({
    operation: "rollback-europe",
    policy: DEFAULT_REGIONAL_DNS_POLICY,
  });

  assert.deepEqual(
    validateApprovedRegionalRollbackBatch(plan.cutoverBatch, {
      env: { APPROVED_ROUTE53_ROLLBACK: "true" },
    }),
    [],
  );
});
