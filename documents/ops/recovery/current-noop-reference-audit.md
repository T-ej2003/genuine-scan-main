# Current broker references in a converged Stage B plan

## Failure and correction

After the authorized infrastructure convergence, a fresh read-only plan correctly
reported no changes. The reference generator nevertheless copied each current
no-op task definition into its atomic-rollover map with `oldArn = currentArn`.
It then treated the live current reference as superseded and demanded a Lambda
update. The production-shaped local fixture reproduced that failure before the
source correction.

The shared broker-mode validator now distinguishes an authenticated current no-op
reference from a stale reference requiring a transition. The pass branch requires:

- exactly one current task-definition change, revalidated by the existing immutable
  no-op/source/image/planned-value contract;
- exactly one broker change whose action is no-op;
- a complete, known broker environment in both before and after observations;
- both planned task-definition maps equal the authenticated live broker map.

A no-op action alone grants no authority. No broker version, release SHA, worker
family or incident-specific exception is added. Stale references still use the
existing exact planned replacement and atomic-broker-update validation. Unknown
references, incompatible maps, duplicate changes, unknown target values and stale
source/image content fail closed. Broker updates remain governed by the existing
update contract; this correction does not introduce redundant update authority.

## Validation and hostile review

The new tests cover the converged twelve-definition plan and plan/audit binding,
stale references in all nine broker modes, unknown revisions, conflicting before
and after targets, duplicate broker/definition changes, changed planned ARN,
missing/malformed/unknown maps, ambiguous environments and stale source content.
Existing exact-replacement, bootstrap-forward, retained-worker and additional
unknown-worker regressions remain part of the validation suite.

Local validation: 233/233 focused reference tests; 966/966 Stage B control-plane
tests; 108/108 historical-runtime tests; 17/17 closure tests; 139/139
state/approval/normal-deployment tests; 21/21 workflow contracts; 95 valid workflow
YAML files; capability graph and dependency closure with zero violations. Static
pull-request closure validation also passes. Hostile self-review found no remaining
actionable issue.

Workflow and capability checks are unchanged. No infrastructure apply, AWS call,
worker lifecycle, printing, RLS, IAM, dependency or MFA change is part of this PR.

## Recovery ordering and checker authentication

Merge only after exact-head independent review and required CI are green. Then
update protected main and rerun fresh canonical Full-RLS preparation, refreshing
expired evidence through existing producers. Do not reapply the completed
infrastructure transaction. Any new plan remains separately governed.

Only after preparation is otherwise ready should the human execute the existing
checker authentication path in their own interactive terminal:

```sh
aws sts get-caller-identity --profile mscqr-production-rls-independent-checker --region eu-west-2 --output json --no-cli-pager
```

The documented chain is checker operator -> MFA-backed
`mscqr-production-independent-checker` ->
`mscqr-production-rls-independent-checker`. Preserve its trust and role boundaries.
Enter MFA only at the terminal prompt; never paste it into chat or store it in
files/logs. The approval-input producer consumes the resulting short-lived
inherited checker session through the existing credential contract. No checker
authentication attempt was made during this code correction.

Recommendation: finish this narrow review/merge, then resume fresh preparation and
stop at the Full-RLS approval boundary. No new recovery mechanism is needed.

## Security-owner reachability revalidation, 2026-10-04

The security owner explicitly authorized revalidation of the existing braces
non-runtime acceptance against clean PR #619 head
`f16d9cff3e26b9640a8e37f3d5e2da251e56221c`. This revalidates the existing risk
decision; it does not narrow the broad input boundary or extend the acceptance.

The canonical implementation and an independent filesystem/hash implementation
both computed 1,913 inputs and hash
`e791d60f13ea0003fab57455cf5f032f86fd17267050e03ae015518edc0e750d`.
The previous binding was
`91f48e97caf1fd0c26ec7cc9e32d3450b60591eae4a7fc4bef79669a8a45e9cf`.
Only the reference-audit generator and its Node test changed within that input
set. The hashing paths, algorithm, unknown-input behavior, runtime enforcement,
and vulnerability thresholds remain unchanged.

An independently instrumented `npm run build` observed braces **3.0.3** executing
four calls with precisely these configured, repository-controlled patterns:

- `./pages/**/*.{ts,tsx}`
- `./components/**/*.{ts,tsx}`
- `./app/**/*.{ts,tsx}`
- `./src/**/*.{ts,tsx}`

The fresh canonical production output contained 96 executable JavaScript artifacts.
A separate fresh diagnostic build exposed 1,606 mapped sources. Inspection found
neither braces library sources nor the affected compile/expand/stringify recursive
walker implementations. AST property-signature detectors were first checked
against the installed affected implementations, then applied to the canonical
JavaScript and diagnostic mapped sources. The canonical artifact manifest
SHA256 was `87f6d02a501ea97c88fd08fb0b86277127d1be9a4bdb34c9638d46255c2f57aa`
(SHA256 of the ordered JSON file/digest/match records). This corroborates the
specific inspected CVE decision; it is not complete generic plugin provenance.

The changed generator/test are not imported by the current Vite or Tailwind
configuration, selected by the frontend Vitest configuration, present in the
build-loaded module trace, or mapped into browser output. Tailwind content globs
do not select them. Frontend Dockerfiles copy scripts into the builder but invoke
the Vite build, not these scripts; Nginx receives only the resulting `dist`.
Backend/worker use the separate backend dependency closure, pruned with
`npm prune --omit=dev`; their lockfile contains no braces. The backend Dockerfile
does not copy either changed file into its runtime. The publisher still selects
that same runtime stage for backend and worker. Production requests do not set
Tailwind patterns or invoke this compilation path.

Fresh OSV Scanner **2.6.0** used the existing recursive, unfiltered command with
`--no-resolve --config=/dev/null --format=json`. It still detected
**GHSA-vfj7-8cjw-p6xm / CVE-2026-93687**, **braces 3.0.3**, **HIGH**, in the
root lockfile's dev group, with no fixed-version event. The finding remains
visible; the unchanged enforcement separately reports
`TIME_BOUNDED_NON_RUNTIME_ACCEPTANCE`.

Only the acceptance's `reachability.inputsSha256` was rebound after these checks.
Scope `frontend-build-only/non-runtime`, advisory/CVE, version, rationale, owner
`@T-ej2003`, creation date and expiry **2026-11-02 (exclusive)** are identical to
the previously authorized record. Automatic expiry and contradictory-runtime
rejection remain enforced. No package, build, runtime, AWS, infrastructure, worker,
printing, checker-MFA or provenance-system changes are part of this revalidation.

Local validation after rebinding passed: 89 OSV/acceptance/expiry/dependency-policy
tests, 966 Stage B control-plane tests, 260 state/normal-deployment/historical-runtime/
closure tests, and 29 workflow contracts. Production dependency audit and the
unfiltered OSV enforcement passed. The fresh production build, 95 workflow YAML
files, and capability/dependency graph (666 capabilities, 213 AWS calls, zero
violations) passed. Complete-diff self-review verified the exact one-field
acceptance change and unchanged build/enforcement/packaging code. Merge still
requires fresh exact-head Codex review and all required CI.
