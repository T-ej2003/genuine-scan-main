import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { certificationEvidencePath } from "../rls/certify-clean-room-database.mjs";

const root = path.resolve(fileURLToPath(new URL("../..", import.meta.url)));
const runner = fs.readFileSync(path.join(root, "scripts/rls/certify-clean-room-database.mjs"), "utf8");
const family = "current-runtime-super-admin-invitation";

test("current-runtime Super Admin invitation is an explicit certification family", () => {
  assert.match(runner, new RegExp(`if \\(env\\.MSCQR_FULL_RLS_CERTIFICATION_FAMILY !== "${family}"\\) return null`));
  assert.match(runner, /backend\/tests\/currentRuntimeSuperAdminInvitationPostgres18\.test\.js/);
  assert.match(runner, new RegExp(`if \\(env\\.MSCQR_FULL_RLS_CERTIFICATION_FAMILY === "${family}"\\) \\{[\\s\\S]*?runCurrentRuntimeSuperAdminInvitationCertification\\(connections, env\\)`));
  assert.match(runner, /result\.currentRuntimeSuperAdminInvitationCertification = finalRun\.currentRuntimeSuperAdminInvitationCertification;/);
  assert.match(runner, /result\.status = result\.certificationFamily === "current-runtime-super-admin-invitation"[\s\S]*?"current-runtime-super-admin-invitation-certified"/);
  assert.match(
    certificationEvidencePath({ MSCQR_FULL_RLS_CERTIFICATION_FAMILY: family }),
    /disposable-certification-result\.current-runtime-super-admin-invitation\.json$/
  );
  assert.doesNotMatch(certificationEvidencePath({}), /current-runtime-super-admin-invitation/);
});
