# Current-release prerequisite ordering: reachability revalidation

This change separates protected broker/image prerequisite preparation from
rotation-dependent application deployment and supplies the missing image-source
argument in the existing overlap validators. It changes no application source,
dependency lockfile, runtime image identity, build pattern or container packaging.

A fresh unfiltered OSV Scanner2.6.0 scan used the existing recursive/no-resolve
Deployment Audit contract. The retained Darwin arm64 scanner SHA256 is
98c460dcd37de25819babd757d04542045b6243113e209edcd4d89fedb0256b4.
The report SHA256 is
e7f8a33f732774b0883f0e4a381b366bb3ae1bf916f31d4064b2af83298ec476.
Only the existing unpatched HIGH braces3.0.3 finding
GHSA-vfj7-8cjw-p6xm / CVE-2026-93687 remains, in frontend build dependencies.

Canonical assertRuntimePackaging, buildBrowserClosure and enforceRuntimeFindings
passed against frozen executable/build inputs
44d8f335df7a4f6fdab1fadfb6c6564874b9305b73c303230f009fb5425a3798.
The browser census includes204 packages and no braces. Backend/worker dependency
locks and Nginx runtime packaging exclude braces; production users cannot supply
build patterns. A shared dependency symlink was rejected during the first browser
attempt; an independent APFS copy restored lockfile-attributable package paths.
No attribution assertion was changed or bypassed.

Only the existing acceptance input binding advances. Owner, scope, rationale,
creation date, runtime exclusions and exclusive2026-11-02 expiry remain unchanged.
The finding remains visible. Private evidence is retained under
/private/tmp/mscqr-current-release-4cade94/prerequisite-order-osv/.
No production mutation occurred during this validation.

The canonical RLS certification package was regenerated because ReleaseTrain is
a source-contract input. All generated SQL changes are the original source hash
replaced by the new authoritative hash; migrationSetDigest remains unchanged.
Canonical full RLS verification and artifact-contract tests passed. This advances
source/role-marker integrity bindings without changing policy SQL behavior.
