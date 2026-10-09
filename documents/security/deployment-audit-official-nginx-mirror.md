# Required CI registry and base-image identity correction

## Exact-head failure census

Original reviewed head: `670d7abc63f81a73856c4a189cef3828dc6d0d90`.
All 13 failed jobs were independently inspected. Twelve failures were Docker Hub
HTTP 429; one was HTTP 500 during a PostgreSQL manifest read. The apt installation
in that job succeeded. No failed job demonstrates an application assertion,
registry-authentication denial, or vulnerability-policy rejection.

| Workflow | Job ID / job | Failed step | Image | Registry / HTTP | Classification |
| --- | --- | --- | --- | --- | --- |
| Deployment Audit | 114029411893 / audit | Build container for scan | node:24-bookworm-slim | Docker Hub / 429 | External registry failure |
| Quality Gate | 114028410251 / docker | Docker verification contract | nginx:1.29-alpine | Docker Hub / 429 | External registry failure |
| Quality Gate | 114028410107 / security | Production read-only RLS canary PostgreSQL contract | postgres:18.4@sha256:3a82e1f… (existing canary pin) | Docker Hub / 429 | External registry failure |
| Quality Gate | 114028410284 / App-only deployment contract and real PostgreSQL | Install PostgreSQL client and start isolated harness | postgres:18.4 | Docker Hub / 500 | External registry failure |
| Auth Security Tests | 114028410741 / db-backed-auth-security | Initialize containers | postgres:18.4 | Docker Hub / 429 | External registry failure |
| Quality Gate | 114028410114 / integration | Initialize containers | postgres:18.4 | Docker Hub / 429 | External registry failure |
| Quality Gate | 114028409849 / frontend | Initialize containers | postgres:18.4 | Docker Hub / 429 | External registry failure |
| Quality Gate | 114028320194 / docker | Docker verification contract | node:24-bookworm-slim | Docker Hub / 429 | External registry failure |
| Quality Gate | 114028320042 / integration | Initialize containers | postgres:18.4 | Docker Hub / 429 | External registry failure |
| Quality Gate | 114028319966 / frontend | Initialize containers | postgres:18.4 | Docker Hub / 429 | External registry failure |
| Quality Gate | 114028320216 / security | Production read-only RLS canary PostgreSQL contract | postgres:18.4@sha256:3a82e1f… (existing canary pin) | Docker Hub / 429 | External registry failure |
| Quality Gate | 114028320279 / App-only deployment contract and real PostgreSQL | Install PostgreSQL client and start isolated harness | postgres:18.4 | Docker Hub / 429 | External registry failure |
| Auth Security Tests | 114028318402 / db-backed-auth-security | Initialize containers | postgres:18.4 | Docker Hub / 429 | External registry failure |

## Shared image contract and legitimate P2

The former audit-only nginx pin was unsafe: production used a mutable tag. That
valid Codex P2 is resolved by the shared `docker/base-image-identities.json`
contract and identical immutable references in both frontend Dockerfiles. The
production web workflow still selects its exact protected release source and
`Dockerfile.ecs-frontend`, linux/amd64, immutable final-image repository, source
labels, signer, and readback. It independently verifies the approved base manifests
before a *new* build. Existing authenticated final-image adoption is unchanged.
No governed production build/publication, deployment, AWS policy, or existing
Stage-B operation was executed. Docker builds used disposable local images only.

The reviewed identities were obtained independently from Docker Hub and Docker's
verified official ECR Public publisher. Full index bytes, amd64 and arm64 manifests,
config digests, and ordered layer digests matched. They preserve the current
intended Node, nginx, PostgreSQL, Redis, and local Alpine fixture contents. The
canary's older pinned PostgreSQL index is preserved exactly; the separate
PostgreSQL 18 certification tag was independently resolved, not conflated with
18.4. Production application code, runtime configuration, deployment safeguards,
trust roots, authorization boundaries and final image identity remain unchanged.
Future builds use these reviewed base bytes instead of silently following tags.
Changing Dockerfile references changes source/build fingerprints and can require
new canonical source-bound images for future releases. It does not relabel or
replay any already-published release artifact.

Routine CI uses only approved digest references. Docker verifies downloaded layers
by digest. The independent verifier hashes index/manifest/config bytes, compares
exact layer identities, and checks each config's linux/amd64 or linux/arm64
architecture. Missing credentials, HTTP 401/429/500, changed bytes, missing platform,
wrong registry, unknown config, mutable substitution, partial updates, and audit-only
overrides fail closed. There is no mutable-tag fallback or copied expected value.
PostgreSQL harness assertions now require the exact approved reference *and* a
reviewed native content ID. Classic Docker config IDs and containerd index/manifest
IDs are distinguished; arbitrary IDs do not pass. All local labels, tmpfs,
loopback-only port, TLS and database-isolation assertions remain enforced.

Publisher provenance:
https://www.docker.com/blog/news-from-aws-reinvent-docker-official-images-on-amazon-ecr-public/

## Explicit reviewed security-update procedure

1. Run `node scripts/verify-container-image-provenance.mjs --review-upstream`.
   This authenticated read-only review compares current upstream tags to the
   reviewed identities and mirror. Any upstream tag advancement fails visibly.
2. Independently collect the new Docker Hub and official ECR index with
   `docker buildx imagetools inspect <reference> --raw`. Hash/cmp exact bytes, then
   authenticate the amd64/arm64 child manifests, configs and ordered layer digests.
   Review upstream release/security changes and scan the proposed immutable images.
3. Update the lock and **all** affected Dockerfile/workflow/harness references
   together in one source PR. Never update a production reference without the
   audit reference. Run the provenance verifier, regression tests, actual builds,
   vulnerability scans, SBOM and OSV revalidation; obtain review and required CI.
4. Merge only after approval. No automated update or production mutation is
   introduced here. A mutable tag changing after validation cannot change build
   bytes: both production and audit stay on the exact reviewed index until this
   explicit procedure approves the next identity.

## Security policy and findings

The original container Trivy scan at v0.70.0 reported 179 occurrences: **0 critical,
44 high, 83 medium, 50 low, 2 unknown**. These are findings, not a clean-security
claim. All findings are Alpine OS-package occurrences; all 44 high occurrences have
reported fixes (including curl, OpenSSL, expat, XML, HTTP and image libraries).
Prioritize a separate reviewed base-image security update using the procedure
above; this equivalent-registry correction does not silently upgrade packages.
The existing action uses all severities, does not ignore unfixed findings,
and defaults to reporting exit code zero. No container high/critical rejection
threshold is configured in this audit. The stricter npm production-dependency and
OSV runtime gates remain blocking. No finding, severity, threshold, exception
expiry, Trivy scan, IaC scan, SBOM, attestation, CodeQL, Gitleaks or required job is
removed or weakened. Scanner/process failures remain failures. Full reports are
retained and must be reviewed; runtime CVE remediation is not disguised as this
registry reliability correction.

## Hostile review and validation

The regression suite exercises actual public audit command serialization and
shared production inputs; partial/unaligned image updates, mutable references,
foreign registry/config/manifest/layer identities, architecture substitutions,
missing auth, rate limits and stale upstream tags fail closed. Approved updates
advance both builders and the lock together. Security and SBOM stages retain
normal fail-on-process-error behavior. Real local frontend/backend builds and
PostgreSQL/TLS/canary tests validate the changed public paths. The canonical RLS
package producer regenerates source-derived digests after authoritative Dockerfile
and workflow changes; SQL executable semantics must remain unchanged. OSV evidence
is refreshed only after a new canonical build and unfiltered scan, retaining the
existing expiry and scope.

The Dockerfile frontend and QEMU tooling retain their existing vendor registries;
no unverified alternative is introduced for them. They did not cause these 13
failures. Any later authenticated failure there remains an external/tooling
boundary to diagnose, not permission for an unrelated image substitution.

PR #647 remains unchanged. Neither PR is merged automatically. Production
mutations remain zero.

### Final local hostile-review record

P0: none. P1: none. P2: the audit/production mutable-tag divergence is corrected
by the shared immutable contract. Review also caught and corrected image-family
substitution in the lock verifier and accommodated Docker's authenticated classic
versus containerd content-ID representations without accepting arbitrary IDs.
All changed helper callers, build inputs, workflow commands, defaults and security
stages were inspected. No known security/provenance finding remains in this diff.

Local validation passed: 20 image-contract regressions; 161 focused security,
OSV and packaging tests; 1,620 Stage-B tests (1,618 passed, two existing skips);
29 real app-only PostgreSQL tests; TLS, canary and operator-boundary checks;
actual audit amd64/arm64, production-frontend amd64 and backend builds; real
Compose proxy tests; all 97 workflow YAML files; source security guardrails;
capability/dependency closure; canonical RLS verification and `git diff --check`.
All eight regenerated SQL files retain identical executable semantics; only
canonical source/migration digests changed. A fresh unfiltered OSV scan and
canonical 204-package browser closure reauthenticated the existing non-runtime
finding, preserving its November 2 expiry. Trivy repeated the same 179 findings;
SPDX 2.3 SBOM generation (1,138 packages) and IaC scanning succeeded.

The first corrected-head CI additionally exposed two independently diagnosed
issues: the existing impact classifier did not recognize the new lock/two test
Compose inputs, and ECR Public returned HTTP 429 during provenance reads. The
lock is now explicitly image-affecting for backend and frontend; only the two
named disposable harnesses are tooling-only. Unknown neighboring paths still
fail closed. Registry reads retry the same URL at most four times with bounded
backoff for 429/temporary 5xx responses. Each successful response still undergoes
full authentication; exhaustion, auth failure or substituted bytes still fails.
The expanded suites contain 21 image-contract and 31 image-impact regressions.
GitHub also verified all seven mirror identities, then exposed a test placement
error: the Docker-only job has no host `node_modules`. The image regression suite
now runs in required Deployment Audit after its existing locked `npm ci`; the
Docker job retains the dependency-free provenance verifier and actual builds.
No dependency or required test was removed or bypassed.

Required GitHub CI and a new exact-head review remain necessary before merge;
local results do not substitute for them. Keep security updates in the documented
reviewed update process so immutable pinning does not silently defer CVE fixes.
