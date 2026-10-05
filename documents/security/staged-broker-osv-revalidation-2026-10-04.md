# Staged broker candidate: explicit security-owner revalidation

Date: 2026-10-04 UTC. Owner: @T-ej2003 (existing acceptance owner).
This records the separately authorized revalidation of the complete local staged
broker candidate, not a new risk acceptance or a claim of universal plugin provenance.

- Base: `be45d6bf0dc79e81f7ecd5db7a71eeeedf9e395e`.
- Prior broad input hash: `e791d60f13ea0003fab57455cf5f032f86fd17267050e03ae015518edc0e750d`.
- Revalidated broad input hash: `e39ae7f5a60a203c7a345a188de898121cb082851a34df0d94c4d8e902dcfe8f`.
- Existing boundary unchanged: 1,913 prior files, 1,925 candidate files; 33 changed
  inputs (21 modified, 12 added), no removed input. The six changed/new documents
  and IAM/capability artifacts under documents/ are outside the existing boundary;
  they have also been inspected and do not change compiler/packaging behavior.
- Acceptance advisory/package/version/scope/rationale/owner/expiry are unchanged.
  Expiry remains **2026-11-02, exclusive**. Only reachability.inputsSha256 changes.

## Fresh execution and artifact evidence

The canonical `npm run build` was repeated with temporary Node preload tracing,
private fresh output and diagnostic sourcemaps. The tracer observes the installed
braces export and records actual caller stacks; it does not modify return values.
Four calls used exactly:

```
./pages/**/*.{ts,tsx}
./components/**/*.{ts,tsx}
./app/**/*.{ts,tsx}
./src/**/*.{ts,tsx}
```

The observed caller path is Tailwind content discovery -> fast-glob task processing
-> micromatch.braces -> braces expansion. The configuration supplies literal paths
from tailwind.config.ts. Chokidar's installed watcher path also expands brace paths;
production compilation is not watch mode. compile/expand/stringify recursive AST
walkers require attacker-controlled deeply nested brace patterns to exhaust the
stack. No such pattern originates in production request, QR, database or queue data.

Fresh browser output and all 1,606 mapped sources were inspected against the affected
library/recursive-walker implementation. No braces source, affected walker signals,
application import, or audited build-hook copying path was found. This combines
actual artifact inspection with current configuration/call-path review; module IDs
or absent node_modules in Nginx alone are not an absence proof. The generic gate
continues rejecting UNKNOWN provenance without this exact reviewed acceptance.

Backend and worker use backend/Dockerfile's pruned backend dependency closure;
its lock has no braces instance. Both frontend Dockerfiles copy only fresh /app/dist
to Nginx, with no Node/Tailwind runtime. The shared Stage B contract actually copied
into backend/worker imports only node:crypto and adds qualified Lambda configuration
validation, not pattern execution. Broker publication packaging uses separate locked
AWS SDK dependencies, also without braces. Runtime packaging assertions pass.

The dependency graph, package/lock files, Vite/PostCSS/Tailwind configs, frontend
application, backend/worker source and Docker packaging have not changed from the
previous review. No changed input was loaded during the instrumented frontend build.
A transitive local-import inspection covered 131 governance/helper files; external
imports are AWS SDKs, Prisma, argon2, js-yaml and jszip, not braces/Tailwind/globbing.
The locked braces tree remains exclusively the reviewed Tailwind path.

Publication plans, approvals, metadata, Terraform/AWS output, source SHA/tree,
artifact paths, environment values and task maps are parsed/validated/hashed or
passed as fixed argument-array values to governed commands. They are not used as
Tailwind content configuration, browser inputs, or braces patterns. Temporary
package npm installation uses the canonical broker package lock, not the frontend
Tailwind package. No new braces call/input source or production attacker path exists.

Unfiltered OSV source scan still detects braces@3.0.3, GHSA-vfj7-8cjw-p6xm /
CVE-2026-93687, HIGH, with no fixed version. The raw report remains visible and the
separate deployment disposition remains TIME_BOUNDED_NON_RUNTIME_ACCEPTANCE.

## Complete changed-input review

| Input | Change | Reachability classification |
|---|---|---|
| `scripts/apply-production-green-stage-b.mjs` | modified | Governed deployment evidence/plan/CAS path; standard JSON/hash/argv operations, no braces/glob calls; not loaded by build or copied into browser/server runtime. |
| `scripts/aws/apply-production-full-rls-release.mjs` | modified | Governed deployment evidence/plan/CAS path; standard JSON/hash/argv operations, no braces/glob calls; not loaded by build or copied into browser/server runtime. |
| `scripts/aws/commit-production-component-security-state.mjs` | modified | Governed deployment evidence/plan/CAS path; standard JSON/hash/argv operations, no braces/glob calls; not loaded by build or copied into browser/server runtime. |
| `scripts/aws/generate-production-green-stage-b-capability-graph.mjs` | modified | Static IAM/capability classification; parses source/JSON and canonical hashes, never invokes frontend compilation. |
| `scripts/aws/production-green-stage-b-contract.mjs` | modified | Copied backend/worker contract: only node:crypto import; new qualified-version validation has no pattern evaluation. |
| `scripts/aws/run-stage-b-staged-broker.mjs` | added | Governed deployment evidence/plan/CAS path; standard JSON/hash/argv operations, no braces/glob calls; not loaded by build or copied into browser/server runtime. |
| `scripts/aws/stage-b-deployment-contract.mjs` | modified | Governed deployment evidence/plan/CAS path; standard JSON/hash/argv operations, no braces/glob calls; not loaded by build or copied into browser/server runtime. |
| `scripts/aws/stage-b-staged-broker-authorization.mjs` | added | Governed deployment evidence/plan/CAS path; standard JSON/hash/argv operations, no braces/glob calls; not loaded by build or copied into browser/server runtime. |
| `scripts/aws/stage-b-staged-broker-closure.mjs` | added | Governed deployment evidence/plan/CAS path; standard JSON/hash/argv operations, no braces/glob calls; not loaded by build or copied into browser/server runtime. |
| `scripts/aws/stage-b-staged-broker-contract.mjs` | added | Governed deployment evidence/plan/CAS path; standard JSON/hash/argv operations, no braces/glob calls; not loaded by build or copied into browser/server runtime. |
| `scripts/aws/stage-b-staged-broker-executor.mjs` | added | Governed deployment evidence/plan/CAS path; standard JSON/hash/argv operations, no braces/glob calls; not loaded by build or copied into browser/server runtime. |
| `scripts/aws/stage-b-staged-broker-observations.mjs` | added | Governed deployment evidence/plan/CAS path; standard JSON/hash/argv operations, no braces/glob calls; not loaded by build or copied into browser/server runtime. |
| `scripts/aws/stage-b-staged-broker.mjs` | added | Governed deployment evidence/plan/CAS path; standard JSON/hash/argv operations, no braces/glob calls; not loaded by build or copied into browser/server runtime. |
| `scripts/aws/verify-production-dependency-closure.mjs` | modified | Static IAM/capability classification; parses source/JSON and canonical hashes, never invokes frontend compilation. |
| `scripts/tests/fixtures/staged-broker-runtime.mjs` | added | Test/fixture only; not selected by content globs or runtime Docker COPY; not loaded by build. |
| `scripts/tests/fixtures/staged-broker.mjs` | added | Test/fixture only; not selected by content globs or runtime Docker COPY; not loaded by build. |
| `scripts/tests/production-dependency-closure.test.mjs` | modified | Test/fixture only; not selected by content globs or runtime Docker COPY; not loaded by build. |
| `scripts/tests/production-full-rls-release.test.mjs` | modified | Test/fixture only; not selected by content globs or runtime Docker COPY; not loaded by build. |
| `scripts/tests/production-green-stage-b-identity-capabilities.test.mjs` | modified | Test/fixture only; not selected by content globs or runtime Docker COPY; not loaded by build. |
| `scripts/tests/stage-b-administrator-phase-split.test.mjs` | modified | Test/fixture only; not selected by content globs or runtime Docker COPY; not loaded by build. |
| `scripts/tests/stage-b-staged-broker-closure.test.mjs` | added | Test/fixture only; not selected by content globs or runtime Docker COPY; not loaded by build. |
| `scripts/tests/stage-b-staged-broker-executor.test.mjs` | added | Test/fixture only; not selected by content globs or runtime Docker COPY; not loaded by build. |
| `scripts/tests/stage-b-staged-broker.test.mjs` | added | Test/fixture only; not selected by content globs or runtime Docker COPY; not loaded by build. |

| `scripts/rls/sql/generated/10-roles.sql` | modified | Canonical generated SQL; only source-contract/derived package binding markers change. No braces invocation, compiler input, browser payload, or production application packaging path. |
| `scripts/rls/sql/generated/11-ownership-grants.sql` | modified | Canonical generated SQL; only source-contract/derived package binding markers change. No braces invocation, compiler input, browser payload, or production application packaging path. |
| `scripts/rls/sql/generated/15-migration-preflight.sql` | modified | Canonical generated SQL; only source-contract/derived package binding markers change. No braces invocation, compiler input, browser payload, or production application packaging path. |
| `scripts/rls/sql/generated/20-context-helpers.sql` | modified | Canonical generated SQL; only source-contract/derived package binding markers change. No braces invocation, compiler input, browser payload, or production application packaging path. |
| `scripts/rls/sql/generated/21-runtime-grants.sql` | modified | Canonical generated SQL; only source-contract/derived package binding markers change. No braces invocation, compiler input, browser payload, or production application packaging path. |
| `scripts/rls/sql/generated/30-policies.sql` | modified | Canonical generated SQL; only source-contract/derived package binding markers change. No braces invocation, compiler input, browser payload, or production application packaging path. |
| `scripts/rls/sql/generated/40-post-apply-verification.sql` | modified | Canonical generated SQL; only source-contract/derived package binding markers change. No braces invocation, compiler input, browser payload, or production application packaging path. |
| `scripts/rls/sql/generated/90-clean-room-role-cleanup.sql` | modified | Canonical generated SQL; only source-contract/derived package binding markers change. No braces invocation, compiler input, browser payload, or production application packaging path. |

| `scripts/tests/production-green-stage-b-permission-preflight.test.mjs` | modified | Permission simulation test only; verifies eight exact read-only broker prerequisites and denial behavior. Not loaded by frontend build, selected by content globs, or copied into application runtime. |

The five IAM/capability documents change reviewed read permissions and generated
capability metadata. They are not compiler plugins/content patterns or runtime
payloads. The protocol documentation is prose. Neither category is an exclusion
added to the boundary: the hashing implementation is unchanged.

## Reproduction and security conclusion

Evidence: staged-broker-osv-revalidation-2026-10-04.json records input hashes,
changed-file before/after hashes, actual caller stacks, affected-library hashes and
fresh executable artifact hashes. Temporary detailed logs remain in
/private/tmp/mscqr-staged-broker-security-revalidation/.

Run the unfiltered OSV source scanner, then
`node scripts/check-osv-runtime.mjs <fresh-unfiltered-report.json>`; the latter
performs another fresh canonical browser build and verifies the same broad snapshot
before/after build and at enforcement. Run deployment-osv-policy,
osv-non-runtime-acceptance, dependency-audit-policy and osv-deployment-expiry tests.

Conclusion for this exact candidate: build execution YES; backend, worker, Nginx
and inspected browser execution NO; production attacker pattern control NO. The
specific existing security conclusion remains unchanged. Any future input drift,
contradictory runtime evidence, changed package/version, patch availability, missing
report or expiry blocks according to the unchanged enforcement contract.

Recommendation: retain expiry enforcement and permanent plugin-emission hostile
regressions. Pursue upstream patched dependency remediation separately when available;
do not expand this broker recovery into a styling migration.

## Final candidate validation and hostile review

- Staged broker: 95/95 pass. Existing Stage B/control plane: 966/966 pass.
- OSV policy, acceptance, plugin attacks and automatic expiry: 89/89 pass.
- Fresh unfiltered OSV scan finds exactly the existing HIGH, unpatched advisory;
  enforcement and another canonical fresh browser build pass with one visible
  time-bounded acceptance.
- Capability/dependency closure, all 95 workflow YAML files, production dependency
  audit, fixture secret-shape checks and AWS DR static safety checks pass.
- Expanded state/normal-deployment/closure/workflow sweep: 367/368 pass. The sole
  extra failure is the unchanged workflow-delegation-registry diagnostic test
  (line 37), whose lookup passes undefined to delegationKey. It reproduces on an
  untouched archive of be45d6b with the identical TypeError (3/4 pass in that file).
  Its RLS scan/test/source files are unchanged and it is not invoked by the
  required workflow contract command. No assertion was waived or changed.
- Final hostile review found no candidate defect: acceptance diff is exactly one
  hash; all other acceptance fields, checker/CAS authority, reviewed-input code,
  dependency manifests/configs/runtime packaging and vulnerability visibility
  are unchanged by revalidation. Candidate broad hash was independently checked
  after the final source/test edits. No AWS or production command was executed.

## CI correction revalidation

The first exact-head CI run caught stale generated Full-RLS source/package bindings
for the two intentionally modified governed scripts. Canonical `rls:full-generate`
updates only source identities, derived checksums and clean-room binding markers;
SQL privileges and policy semantics remain unchanged. `rls:full-verify` passes.
The same stale package caused Stage B closure failure. Gitleaks v8.24.2 also
classified a long named import as a generic API key; multiline formatting corrects
the false positive without an ignore or scanner-policy change. Fresh instrumented
compilation after both corrections observed the same four trusted patterns and
identical executable browser artifacts. All 33 broad-boundary changed inputs are
reviewed above, including eight generated SQL binding artifacts.

### Exact-head review correction

The first external review identified a terminal generation race: a second
component-state read could differ from the wrapper baseline even though the CAS
succeeded. The private commit helper now returns its own authenticated baseline
for the staged terminal assertion. A behavioral regression reproduces the old
false failure, requires one pre-CAS read, and proves idempotent terminal replay.
No CAS or historical-retention condition is relaxed. Fresh compilation after
this source/test correction retains the same four brace patterns and identical
browser executable artifacts. The final reviewed-input hash above covers it.

### Permission-preflight census correction

The complete CI closure command additionally caught an old 258-evaluation test
baseline. Seven reviewed read-only manifest entries produce eight resource
evaluations (GetPolicy has two exact scopes), yielding 266. The corrected test
asserts all eight action/resource tuples and individually rejects denial of each;
38 forbidden evaluations remain required. This is test drift, not a permission
policy change. Fresh compilation after the test correction retained the same
four trusted brace patterns and identical executable browser artifacts.

### Ordinary apply and exact-principal review corrections

An additional exact-head review identified the ordinary Terraform executor as a
possible fallback around staged authorizations/CAS. Its physical spawn boundary
now rejects all broker function/alias mutations, including create/delete/replace,
unknown aliases, malformed action sets and address/type spoofing. The production
apply wrapper passes its authenticated saved-plan census into this guard. Permanent
behavioral tests prove zero Terraform spawns both directly and through the ordinary
saved-plan wrapper. Historical full-profile classification remains available for
auditing; it cannot authorize an unguarded alias mutation. Existing injected apply
stubs exercise artifact/reservation mechanics separately from this guarded physical
executor. No-op broker resources and ordinary application lanes retain behavior.

The checker also verifies its KMS signature after signing. Capability graph and
dependency closure now share the exact execution-principal resolver and represent
Verify for both checker and release deployer; removing either principal is rejected.
The existing checker SignExactStageBApproval policy already includes Verify; no new
IAM privilege is introduced. Fresh compilation after these corrections observed the
same four trusted braces patterns and identical executable browser artifacts.

The final historical-runtime ordering assertion now matches the authenticated two-argument apply call. Fresh instrumented compilation after this test-only correction preserved all four patterns and every executable artifact hash. The broad binding includes this correction.

### Final traffic-census and terminal-readback review corrections

The previous reader falsely accepted new version policies, function URLs, event mappings and published versions created during its census. All four attacks were reproduced against the prior exact head. A shared complete traffic census now runs again before returning authority, with role/configuration consistency readbacks. Behavioral tests reject every concurrent route/census change. Terminal readback accepts validated later backend/frontend generations only while the committed security component, its provenance and historical retention remain exact; same-generation document equality remains required. This preserves the real security CAS without failing after unrelated successful writes. The 100 focused tests pass. Fresh instrumented production compilation after the complete correction observes identical four trusted patterns and executable artifacts; all changed inputs remain outside compiler execution. Acceptance metadata and broad boundary remain unchanged.

The ordinary production executor now performs its shared pure census check immediately after saved-artifact authentication, before verification-ready status, reservation or spawn uncertainty. Physical execution checks again. Mocked apply stubs only exercise reservation mechanics and provide no CLI bypass. The default-executor regression proves broker rejection creates zero reservation entries; 154 permission/apply tests pass. Fresh compilation after this correction retains all observed input patterns and artifact hashes; the final broad binding covers these changes.

### Authenticated maker signing correction

The signing boundary now requires the real release-profile STS caller in addition to the independently authenticated checker. A claimed maker must equal that authenticated account/role/session; the handler supplies the governed executor reader rather than trusting request fields. Both publication and cutover reject forged, missing, wrong-account and checker-role maker identities before KMS Sign. All 102 focused tests pass; capability coverage remains exact without new permissions. Fresh instrumented compilation after the correction retains the same four repository-controlled patterns, affected-library version and browser executable hashes. No staged approval or metadata input reaches brace evaluation, and the existing scope/expiry/broad boundary remain unchanged.

### Required-CI regression integration

`package.json` is the additional broad-boundary input: only the existing Stage B control-plane test command gains the three new staged-broker suites. Dependencies, lockfile, production build command and runtime package semantics remain identical to the reviewed tree. The actual production build was rerun after this final manifest edit; every executable artifact hash and all four trusted brace patterns remain exact. This brings the complete reviewed changed-input census to 33, including this root-manifest test-command edit. The acceptance remains exact, visible and expiring.
