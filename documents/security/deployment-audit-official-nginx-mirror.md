# Deployment Audit official nginx mirror

The PR audit failed twice on 2026-10-09 while Docker Hub returned HTTP 429 for
`nginx:1.29-alpine`. It has no Docker Hub login, registry credential, or persistent
Docker build cache. Repository and environment secret-name inventories contain
no Docker Hub credentials. Governed production ECR publication roles are not
repurposed for PR audits. A private ECR cache could not be authenticated locally
because the available operations profile has no active credentials.

Docker officially publishes its Docker Official Images to ECR Public:
https://www.docker.com/blog/news-from-aws-reinvent-docker-official-images-on-amazon-ecr-public/

Read-only registry requests independently authenticated the following identical
manifest bytes from Docker Hub `library/nginx:1.29-alpine` and ECR Public
`docker/library/nginx:1.29-alpine`:

- Index: `sha256:5616878291a2eed594aee8db4dade5878cf7edcb475e59193904b198d9b830de`
- Linux/amd64 manifest: `sha256:3bcf852aed06467cf075c6105892e4d5a6ebbbafa0ce22d35062db9e90ddef4c`
- Config: `sha256:812d47f806db497c53f9b47e76bdab38bcf5d724c69d3986df5ee4336c210559`
- All eight layer digests match, as does the complete index (all platforms).

The audit-only named build context resolves this nginx input from the immutable
official ECR digest. Docker documents this override mechanism at
https://docs.docker.com/build/concepts/context/#example-pin-or-override-images
Production Dockerfiles, release identities, permissions, build contents, Trivy
configuration, OSV, CodeQL, Gitleaks, IaC scan, SBOM, attestations, and artifact
upload remain unchanged. No registry credentials or production writes are added.

The focused test executes the actual workflow build command with a recording
Docker function and checks the unchanged scan/SBOM boundaries. The full container
build and scan must pass in GitHub Actions; the local Docker daemon is unavailable.
Hostile review checks: the mirror is Docker's official publisher, the digest
matches the original image, no mutable fallback or skipped scan exists, and
production builds do not consume this audit-only override. P0/P1/P2 found: zero.

The pinned image needs an explicit new provenance/digest review when updating
nginx. Node and the Dockerfile frontend still use their existing Docker Hub paths;
this focused change does not introduce unverified mirrors for them.

Validation: 98 focused registry/workflow/security/OSV tests passed; all 97 workflow
YAML files validated; security guardrails and `git diff --check` passed. A fresh
unfiltered OSV scan and canonical browser build authenticated 204 browser packages,
with no braces runtime inclusion. The existing non-runtime acceptance was
revalidated against input fingerprint
`f1ebc1612fa19a90bede0f419b854f8ebb7f346de7af8d022803a97f92c1302e`;
its finding, owner, scope, rationale, and exclusive 2026-11-02 expiry are unchanged.
