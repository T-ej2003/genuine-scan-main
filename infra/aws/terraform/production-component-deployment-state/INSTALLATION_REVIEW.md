# Component installation boundary review — source only

## Runtime readback correction

### Issuance propagation integration

Normal installation and cleanup now poll fixed read-only session-proof operations
before their single mutation-capable invocation. The same in-memory 900-second
session is retained while CloudTrail issuance becomes visible. Proof probes still
authenticate the fixed broker, durable authorization, signed STS identity and MFA
issuance; they cannot claim ownership or write IAM/S3. Polling lasts at most five
minutes and reserves two minutes before credential expiry. Missing/invalid proof
at that boundary stops without invoking INSTALL/CLOSE. No automatic mutation
retry or new session issuance occurs inside the loop. The 96 directly affected
broker/archive/session/configuration tests pass offline.

The recovered runtime fixture incorrectly returned a runtime ARN from
`GetRuntimeManagementConfig` in `FunctionUpdate` mode. The
[AWS API contract](https://docs.aws.amazon.com/lambda/latest/api/API_GetRuntimeManagementConfig.html)
returns null there. Runtime identity is now authenticated from
`GetFunction.Configuration.RuntimeVersionConfig` and compared with the durable
bootstrap record; the separate management call must still prove FunctionUpdate.
Null/omitted control ARN is accepted, missing resolved runtime identity is not.
The configuration and fixed-broker suites pass 59 offline tests. Bootstrap and
Terraform execution integration remain unfinished; this is not an activation gate.

## Fixed broker bootstrap transaction checkpoint

### Identity transaction composition checkpoint

The internal first-bootstrap transaction now composes exact creation/readback of
the five execution identities with the fixed broker publication transaction.
Its fixed S3 journal is conditionally reserved before writes, and closure is
conditional on the owned ETag plus full IAM/broker readback. Accepted-but-lost IAM
and S3 responses are classified by live readback, not replay. Concurrent starts
have one reservation winner. The production-shaped offline adapters exercise ten
IAM writes, eight Lambda writes and reservation/closure; 58 focused tests pass.

This checkpoint deliberately does not expose an administrative CLI. A reserved
incomplete bootstrap has no automatic takeover; the administrative issuance and
authenticated restart/recovery boundary remain unfinished. Do not confuse the
normal broker's implemented STS-expiry recovery with this exceptional initial
bootstrap. No lease age, local marker or manual S3 deletion can unlock it.

The internal bootstrap transaction now creates the source-derived ZIP function,
sets reserved concurrency and FunctionUpdate runtime management, and publishes
the three fixed semantic versions. Publication binds both AWS RevisionId and
CodeSha256. Only the description changes between publications; no code-update,
alias, resource-policy, alternate-role or generic configuration API is exposed.
AWS requires a configuration/code change between versions, as documented by
[PublishVersion](https://docs.aws.amazon.com/lambda/latest/api/API_PublishVersion.html).

Each mutation rechecks authorization and the package's current source manifest.
Every resume reads live version/configuration inventories before choosing a
missing write. Unknown versions, source/code/configuration drift and resource
policies fail closed. Lost responses after each of the eight bootstrap writes
are covered by offline readback/recovery tests with no duplicate write.

This is an internal transaction, not a production-ready bootstrap CLI. Its
authorization, exceptional bootstrap principal, identity transaction and durable
reservation composition still need wiring. The 34 transaction tests are mocked
AWS transport tests, not proof of live deployment permissions or final readiness.

## Dedicated bootstrap approval checkpoint

The first-bootstrap approval workflow is separate from normal installation. It
has no AWS credential acquisition, OIDC permission or mutation step. Its exact
environment requires the sole authorized User reviewer, no administrator bypass
and exact main-only access. It constructs a clean-source package after approval
and binds the five execution identities, trust/policy hashes, bootstrap capability
set, three broker configurations, package/manifest, transition, source and expiry.

The shared environment verifier preserves the existing installation policy and
adds only the fixed first-bootstrap environment. The authorization suites pass
74 offline tests, including real child-process rejection of unsupported publisher
commands. Execution still must independently authenticate the completed GitHub
run/artifact and archive the original approval durably before AWS writes; this
checkpoint does not expose an executable administrative bootstrap command.

The execution-side archive verifier now reuses the strict GitHub transport and
ZIP checks used by normal installation. Bootstrap selects only its fixed workflow,
environment and single archive member. A completed successful first-attempt run,
exact reviewer, repository IDs, artifact SHA256, current protected source,
transition and locally rederived package bindings are all required. There is no
local approval path. Thirty-six archive transport tests pass across the two
boundaries. The preceding complete focused component/credential sweep passed
441 tests, including the clean-source package reproducibility test; this does
not substitute for final validation once remaining execution paths are finished.

Baseline: `bc6ac2ead8b750d9d99cc179d8bb321956fa7a8e`.
Implementation remains uncommitted on
`codex/component-infrastructure-install-permission`. No production execution,
permission activation, plan, apply, bootstrap or deployment occurred.

## Blocking findings

## Implementation continuation: bootstrap-owned broker decision accepted

The owner has now authorized the exact broker deployment and execution role as
part of the first bootstrap. The decision requests below are historical and
must not be raised again. Existing work is preserved; no production action is
authorized by this source implementation.

The implementation now includes offline-tested contracts for:

- permanent installation and cleanup session roles without IAM writes or
  broker-deployment permissions;
- separate immutable invocation versions: installation `:1`, cleanup `:2`,
  authorization publication `:3`, with no unqualified/alias invocation;
- an exact authorization-publisher identity for the approved GitHub workflow,
  so installation credentials cannot manufacture archived approval;
- Lambda configuration/default normalization that rejects unexpected fields,
  plus separate concurrency, signing-state and runtime checks;
- a broker-owned, fixed-key authorization archive with conditional first write,
  exact readback after an ambiguous result, and a distinct concurrent-CAS loser;
- cleanup authentication from durable AWS evidence after artifact expiry;
- a conservative expiration predicate which explicitly requires independently
  authenticated AWS session metadata rather than an unsigned local receipt.

These are **contract implementations, not a completed execution path**. They
are not yet connected to bootstrap/controller/broker workflow execution. The
current archive implements initial reservation, not fresh-authorization recovery.
The old root-controller and local Terraform execution remain pending replacement.
The final package supply chain, executable role inventory, STS issuance/fencing,
isolation runner, workflow wiring and full lifecycle tests remain required.
Do not treat the passing new unit tests as proof of those unimplemented paths.

The publication identity must use a reusable authorization workflow that actually
emits the bound `job_workflow_ref` OIDC claim; the previous non-reusable workflow
does not satisfy that new trust contract. Workflow wiring must resolve this
before any PR or execution readiness claim.

Initial bootstrap may provision these trust anchors once. `BROKER_CHANGE` and
`IDENTITY_CHANGE` are future separately governed operations, not initial
bootstrap replay or normal controller commands. Recommendation: keep normal
controllers invocation-only; do not add permission-management convenience APIs.

### New decision: broker deployment ownership cannot belong to the session controller

The one-time **identity bootstrap exception is now authorized** for source
implementation. It resolves the administrative-identity prerequisite below;
that earlier request is historical, not an outstanding authorization request.
Protected main was reauthenticated at the baseline above. No live operation
has been performed.

Before defining the permanent installation-role policy, a source-derived
counterexample exposed a further ownership decision. Moving the current
controller's calls unchanged into an expiring session would grant that role:

1. creation/replacement of `mscqr-production-component-iam-installer` code;
2. installation of the provisioner execution role's inline capability;
3. invocation of that function.

The broker capability permits `iam:PutRolePolicy` on the existing
`mscqr-production-release-deployer`. Its conditions bind authorization expiry
and the exact **unqualified function ARN**, not the code hash or policy bytes.
Replacement code running in that same function would satisfy the ARN condition
and could write a different release-role policy. The human bootstrap operator
already has the source-defined MFA assumption path into the release role.
Even a short-lived controller session could therefore leave persistent expanded
authority behind. No such policy was submitted, and no Lambda was created or
changed: this is a static capability-composition counterexample, not a live
exploit or an IAM simulation result.

The local package/hash assertions protect the supported CLI path but do not
restrict direct use of the resulting AWS credentials. Expiration, lease CAS,
and the absence of direct self-policy writes do not fix this composition.
Retain `lambda:SourceFunctionArn`; it is useful but is not code authentication.
AWS documents its unqualified-ARN semantics in
[Using source function ARN](https://docs.aws.amazon.com/lambda/latest/dg/permissions-source-function-arn.html).

Reproduction inspected the current `temporaryInstallationPolicies()` result:
the release-role PutRolePolicy statement has only `ArnEquals` and
`DateLessThan` conditions, and the controller contains CreateFunction,
UpdateFunctionCode and PutRolePolicy calls. The original five component IAM
objects remain outside Terraform ownership.

Recommended architectural decision: make the **fixed broker executable and its
execution authority** owned by the separately governed first bootstrap, rather
than the normal installation session. The installation session must not be
able to replace broker code/configuration/trust or grant broker permissions.
The fixed broker must authenticate fresh approval itself; it must not trust an
installer-writable manifest as authorization. Future code/identity changes
belong to a separate change transition, not initial-bootstrap replay.

This expands the newly authorized identity-only bootstrap to own the exact
broker deployment and its execution role, including any separately justified
exact Lambda PassRole requirement. Obtain that ownership decision before
encoding a permanent role with the unsafe combination above. All existing
implementation is preserved. No PR, successful final validation, or resolution
of the three preceding execution-security findings is claimed.

### Administrative-session prerequisite assessment

Protected main was freshly fetched and remains the baseline above. Read-only
IAM inspection found no component-install administrative role. The existing
human-MFA release-deployer and Stage-B publisher-bootstrap roles do not grant
the new component executor-role/function installation authority. The app-only
provisioner is OIDC-only and targets different, boundary-constrained roles;
the initial-activation bootstrap is also OIDC-only and targets other stacks.
Reusing those identities would require changing their existing governance.

AWS STS does not synthesize missing authority:

- `AssumeRole` session policies intersect the assumed role's existing policy;
  they cannot grant the missing installation permissions.
- `GetFederationToken` accepts a scope-down policy but its credentials cannot
  make IAM API calls.
- `GetSessionToken` has no scope-down policy parameter. Root-issued temporary
  credentials retain root authority, even though they expire. This does not
  implement the requested exact installation or cleanup-only capability.

References: [AssumeRole](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html),
[GetFederationToken](https://docs.aws.amazon.com/STS/latest/APIReference/API_GetFederationToken.html),
[GetSessionToken](https://docs.aws.amazon.com/STS/latest/APIReference/API_GetSessionToken.html).

The unresolved prerequisite is how the initial narrowly scoped administrative
and cleanup authority is provisioned. The current restriction permits the
long-lived bootstrap principal only to issue sessions, not to create those
missing roles/policies. No role/session was created during this assessment.
Do not implement root temporary credentials as a substitute or repurpose an
unrelated production role.

Recommended decision: separately review an exact, one-time bootstrap of the
component administrative and cleanup identities, before their session-only
controller can run. Installation and cleanup sessions must remain separate;
neither may modify its own authority. This requires an explicit exception for
the initial identity bootstrap, not permission for the controller to use root.
Until that decision, all three execution-security findings remain open; the
preserved implementation must not be pushed as merge-ready. Isolation and
archival cleanup are not claimed implemented or validated by this assessment.

### P1-1: administrative authority is not fenced after controller loss

The controller authenticates the existing root profile and reserves a durable
S3 lease. SIGKILL/host loss can interrupt it between the final lease check and
an IAM/Lambda call. Root authority has no authenticated expiry in this contract.
Deleting or stealing the lease cannot revoke that authority; S3 conditional
writes do not condition IAM requests. Retaining the lease fails closed, but
provides no bounded canonical recovery. The orphan-lease regression proves that
a second controller is rejected without mutation; it does not prove recovery.

Decision needed: an AWS-enforced, authenticated administrative-session lifetime
or revocation boundary, with outstanding-request reconciliation before takeover.
Do not substitute a lease-age threshold or an unsigned operator marker.

### P1-2: Terraform's local process can reach administrator credentials

Terraform receives only a scoped in-memory session, but still runs as the same
OS user with the same credential home as administrator audit/bootstrap. A
malicious provider can bypass environment selection and read those credentials
or use their local credential provider. The policy test proving no IAM writes
in the Terraform role does not prove execution isolation.

Decision needed: a credential-isolated execution sandbox or remote executor
that receives only the scoped table/backend session and cannot access the
administrator home, keychain, process credentials or host control socket.
Changing HOME alone is not an adequate fix.

### P2-1: cleanup depends on retained GitHub artifacts

Cleanup permits authorization expiry but still downloads the original GitHub
artifact. Its 90-day retention can prevent exact-policy removal afterward.
Permissions have expired, but durable closure cannot be completed. Resolve with
cleanup-only use of authenticated fixed-key AWS archival evidence and original
approval bindings; never accept a caller-selected local authorization file.

## Direct sibling repairs already implemented

- Terraform owns one DynamoDB table; the five IAM objects are exclusively owned
  by the fixed-code Lambda broker.
- Public broker input selects only INSTALL/INSPECT and a transition ID, never
  role names, policy names or IAM documents.
- Exact-source documents, package/configuration, capability hashes, approval,
  expiry and conditional journals are checked. Neither scoped executor policy
  permits provisioner self-policy mutation or IAM PassRole.
- Explicit exact-prefix S3 listing proves initial receipt absence; AccessDenied
  is never interpreted as absence.
- AWS SDK retries are disabled so ambiguous writes return to readback recovery.
- Verified receipts cannot reinstall a subsequently removed policy.
- Same-source fresh approval renews closed/expired capabilities after cleanup
  and function quiescence. Broker journal rebinding uses CAS before further
  target writes; verified objects are not rewritten.
- Table wrappers attempt exact-capability cleanup on downstream failure and
  after apply. Ordinary signal cleanup is best effort, not SIGKILL recovery.
- Terraform rechecks extra inline/managed policies on the two new roles.

## Validation meaning

Focused offline tests, lint, document/workflow guards and backend-disabled
Terraform validation exercise source contracts, not production authority.
Read-only simulation allowed 27 Terraform pairs and denied 21 selected negative
cases. Provisioner simulation was inconclusive under the required exact Lambda
context; it must not be relabeled PASS or fixed by weakening that restriction.
The later receipt-listing pair has not been simulated.

No commit, push, PR, CI result or external review is asserted. These findings
must be resolved before declaring the installation lifecycle merge-ready.

Recommendation: keep the IAM/Terraform split, and complete the two execution
isolation boundaries before adding any installation convenience features.

## Bootstrap-owned broker integration checkpoint

The fixed broker entry point now authenticates the bootstrap closure, published
package/configuration/runtime, and all five execution identities before accepting
an authorization or installation request. Execution identity readback checks
exact names, ARNs, paths, session limits, trust, tags, boundary absence, attached
policy absence, and inline policy inventory/document. Paginated inventories are
consumed with bounded, non-repeating markers; incomplete inventories and access
denials fail closed. Installation inputs cannot select IAM documents or targets.

The offline fixed-entry integration test covers the real dispatch path from
authorization archive through five component IAM writes, idempotent readback,
and durable closure. Lost responses after each IAM write resolve by readback.
Cleanup can close the archived authorization without a retained GitHub artifact
and cannot create/delete IAM objects. Drift in the bootstrap execution authority
is rejected before any component IAM mutation. These are mocked AWS transport
tests, **not live AWS verification or proof of effective runtime permission**.

Current focused result: 162 tests passed across fixed broker dispatch,
authorization archive, configuration, identity contract, and IAM state machine.
The former local/root controller has not yet been replaced; bootstrap execution,
session issuance/fencing, authorization renewal, and isolated Terraform execution
remain integration work. Earlier descriptions
of the legacy controller above are not claims that those open boundaries are
resolved. This branch is not ready for activation, push, or external review.

### Deterministic package boundary

`component-broker-package.mjs` assembles only a fixed inventory of runtime source,
source-owned IAM JSON, and locked SDK dependencies. It reuses the repository's
deterministic ZIP implementation. Production packaging requires clean HEAD equal
to origin/main; bootstrap must separately authenticate that remote reference and
the exact approval. The builder accepts no ZIP, source directory, policy path,
dependency path, or replacement document from its caller. npm executes with
scripts disabled, the public registry pinned, isolated empty configuration,
private temporary cache/home, and no inherited credentials.

The real package test creates a disposable local Git fixture, builds twice and
compares complete ZIP bytes, loads the packaged handler/SDKs in a credential-empty
child process, and confirms rejection before AWS access. This proves packaging
and cold-load behavior, not deployment or cross-version compression identity.
The reviewed authorization must bind the actual package hash. Dirty source is
rejected before dependency installation.

### Authorizer trust support

AWS's current [OIDC condition-key reference](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_iam-condition-keys.html)
documents GitHub `job_workflow_ref`, repository/owner IDs, and ref as supported
AssumeRoleWithWebIdentity trust conditions. `job_workflow_ref` identifies a
**reusable** workflow. The dispatch now delegates to
`component-iam-authorization-publisher.yml`; the authorizer trust pins that exact
reusable workflow, main, repository/owner IDs, actor ID, audience and environment.
The environment approval and live approval/source/package verification precede
OIDC acquisition. The resulting 900-second role may invoke only broker version 3
to archive authorization; it cannot install component IAM, deploy the broker,
pass roles or execute Terraform. GitHub artifacts are human audit copies only.

Focused publisher tests reject missing/wrong approval, alternate actor,
repository/fork/workflow/source substitution, reruns, environment bypass,
wildcard branches, and malformed package/transition bindings. Real child-process
tests reject unsupported CLI commands before build or credential acquisition.
The combined publisher, authorization and identity suites pass 192 tests;
workflow YAML, document organization and security-scope lint also pass. No
production OIDC assumption or workflow dispatch is claimed by these tests.

The legacy local controller still consumes the earlier artifact schema. It must
be replaced with the fixed-broker/session orchestration before this branch can
be pushed or used. Passing publisher tests do not close that integration gap.

### Invocation grant and session-proof work

Broker readback now rejects resource-based invocation policies on the base
function and each fixed published version. This is necessary because an added
resource policy could bypass the source-bound authorizer identity policy. Missing
policy and denied policy read are distinguished; denial stops execution. Five
new fixed-dispatch regression cases exercise this boundary.

The session authenticator combines a transition-bound, presigned STS
GetCallerIdentity request with its unique CloudTrail AssumeRole issuance event.
The request has a fixed endpoint/action/region, a signed binding header, and a
locally enforced 60-second proof window. That proof window is **not** a claim
that STS credentials expire in 60 seconds. AWS-returned session expiry, the
900-second requested duration, and the MFA human issuance chain are authenticated
separately. Durable output contains no access key, session token or signature.
CloudTrail legacy date strings are explicitly treated as UTC.

This follows the [AWS IAM Authenticator's signed GetCallerIdentity pattern](https://github.com/kubernetes-sigs/aws-iam-authenticator)
and [AWS's documented STS CloudTrail response evidence](https://docs.aws.amazon.com/IAM/latest/UserGuide/cloudtrail-integration.html).
Twenty-nine offline session tests pass, including wrong caller/account, OIDC or
non-MFA issuance, altered request bindings, ambiguous/missing events, expiry, and
timezone behavior. The broker now uses the fixed STS transport and a bounded,
fully consumed CloudTrail AssumeRole lookup before claiming the fixed
`installation-session.json` record. Its read-only `cloudtrail:LookupEvents`
permission is regional and conditioned on the exact source function ARN; the API
does not support an IAM resource ARN. No caller chooses the lookup operation,
region or evidence key.

The session record is CAS-protected. Reusing the same authenticated session is
idempotent; replacing it requires prior AWS expiry plus the 120-second margin,
fresh explicit authorization, and a new session issued after that boundary.
There is no lease-age takeover. Every broker IAM-write guard rechecks session
ownership and expiration. Closure records include the separately authenticated
cleanup-session metadata. No proof query, access key, session token or signature
is archived. The public Lambda handler sanitizes rejected-request exceptions.

The integrated dispatch, archive, session-proof and session-fencing suites pass
79 tests, including expiry immediately after the first IAM write and exact
partial-state retention. The real locked-package reproducibility/cold-load test
also passes with the pinned CloudTrail SDK. These remain offline transport tests.
The legacy controller is still not safe to execute and has not yet been replaced.
No completed operator lifecycle or live session proof is claimed.

### Fresh approval and scoped client integration checkpoint

The broker archive now retains an authenticated approval lineage. Renewal must
use a new run, the same transition/source/package, an unclosed transition, and
expired prior AWS authority plus the safety margin. Exact live IAM readback
precedes replacement of the authorization archive. A lost response is resolved
by exact readback; CAS contention is not treated as success. The new session
must be issued after fencing, and the IAM journal may bind only a predecessor
present in the authenticated archive. Completed IAM writes are not replayed.

The normal session client uses the canonical named bootstrap-operator credential
boundary and existing hidden-MFA prompt. Root, release-deployer and alternate
users are rejected before MFA/session issuance. Only the exact installation or
cleanup role is requested, for 900 seconds, and STS-returned identity/expiration
are checked. The returned client exposes only fixed broker invocation operations,
not AWS credentials or general SDK clients. A real pinned SDK signer produces
proofs accepted by the broker parser in offline transport tests. This client is
not yet the public installation controller; the old root-based controller must
still be removed before activation or PR publication.

CI path filters now include every component boundary source/test, the reusable
publisher, shared credential/MFA/package helpers, and dependency lockfiles. The
contract job installs both root and locked broker-package dependencies before
running all component tests plus the credential-source contract. The current
combined focused run passes **518 tests** with no skips. This includes retained
legacy-controller unit tests and does not imply that the unfinished CLI/bootstrap
and Terraform isolation paths meet the final security requirements.

### Durable cleanup discovery after recovery

The new cleanup session client can retrieve the original non-secret source,
transition and authorization hash from the fixed broker's `CLEANUP_CONTEXT`
operation on version 2. It requires only the transition identifier from the
operator, not a local authorization file or retained GitHub artifact. The broker
authenticates its bootstrap record, all execution identities, package/configuration,
and absence of resource-policy bypasses before reading its fixed authorization
archive. This read-only operation cannot select a key or perform an IAM/S3 write.

Discovery does not authorize cleanup mutation. `CLOSE` still requires the freshly
issued exact cleanup role, signed STS identity, MFA-backed issuance/expiry proof,
matching archived bindings, and live IAM classification. Substituted coordinates
fail before closure. The source/transport tests include discovery 91 days after
approval and after protected main advances, with zero writes. The 93 directly
affected tests and changed-file ESLint pass. The public legacy controller still
needs replacement; no completed operator lifecycle or production execution is
claimed by this checkpoint.

### Scoped normal controller checkpoint

The legacy 472-line root/admin controller has now been deleted and replaced by
the scoped installation/inspection/closure composition root. It cannot select
an IAM writer, Lambda deployer, administrator profile, temporary-policy installer
or local Terraform adapter. Unsupported historical commands are rejected by real
child-process tests before source/network/credential operations.

Installation authenticates the current reusable publisher's three-file audit
archive, run/source/reviewer/environment and broker publication result before MFA.
Cleanup uses only its durable-context session client; legacy GitHub-artifact-based
cleanup helpers have been removed. Receipt schemas and source movement are checked
before returning success. The updated runbook replaces obsolete administrator
commands instead of documenting them as a fallback.

The directly affected controller, authorization, publisher, capability and
credential-source tests pass (100 tests); changed-source ESLint and diff checks
pass. This is still not the final gate: initial bootstrap and isolated Terraform
execution remain unfinished. No push or production operation is authorized by
this local checkpoint.
