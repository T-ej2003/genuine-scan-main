import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  RESTRICTED_OWNER_SOURCE_EXCLUSIONS,
  validateRestrictedOwnerProjections,
} from "../rls/lib/restricted-owner-projection-contract.mjs";
import { NAMED_SQL_FUNCTION_CONTRACTS } from "../rls/lib/named-sql-function-contracts.mjs";

const repoRoot = path.resolve(import.meta.dirname, "../..");

test("active restricted-owner SQL uses explicit reviewed projections", () => {
  const result = validateRestrictedOwnerProjections({
    repoRoot,
    contracts: NAMED_SQL_FUNCTION_CONTRACTS,
  });
  assert(result.sourcePaths.includes("backend/src/rls-waves/session-c/c02/printingLifecycle.sql"));
  assert.deepEqual(result.excludedSources, RESTRICTED_OWNER_SOURCE_EXCLUSIONS.map((entry) => entry.path));
});

test("restricted-owner projection gate fails closed on prohibited row shapes", () => {
  const temporaryRoot = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-restricted-owner-"));
  try {
    fs.mkdirSync(path.join(temporaryRoot, "sql"), { recursive: true });
    fs.mkdirSync(path.join(temporaryRoot, "backend/src/rls-waves/session-c/c04"), { recursive: true });
    fs.writeFileSync(
      path.join(temporaryRoot, "backend/src/rls-waves/session-c/c04/operatorProcedures.sql"),
      "-- excluded operator-only source\n"
    );
    fs.writeFileSync(
      path.join(temporaryRoot, "sql/boundary.sql"),
      'CREATE FUNCTION app_rls.bad() RETURNS jsonb AS $$ DECLARE row public."User"%ROWTYPE; BEGIN SELECT u.* INTO row FROM public."User" u; SELECT u.id INTO row.id FROM public."User" u; RETURN to_jsonb(row); END $$ LANGUAGE plpgsql;'
    );
    assert.throws(
      () => validateRestrictedOwnerProjections({
        repoRoot: temporaryRoot,
        contracts: [{ definitionLocation: "sql/boundary.sql" }],
        additionalSources: [],
      }),
      /%ROWTYPE[\s\S]*direct table alias wildcard[\s\S]*untyped record field target/
    );
  } finally {
    fs.rmSync(temporaryRoot, { recursive: true, force: true });
  }
});
