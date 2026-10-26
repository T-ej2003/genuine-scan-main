## Git Branch Naming Convention

All development branches must follow this format:

<category>/<short-descriptive-name>

Allowed categories:

- feature/
- fix/
- hotfix/
- security/
- infra/
- ci/
- refactor/
- chore/
- docs/
- test/

Examples:

- feature/manufacturer-qr-allocation
- fix/production-ecr-retention
- infra/ecr-protection-deployment
- security/oidc-trust-hardening
- ci/stage-b-image-classification

Rules:

1. Never prefix branch names with `codex/`, `ai/`,
   `agent/`, or other tool-identifying prefixes.
2. Use lowercase kebab-case.
3. Branch names must describe the engineering change.
4. Keep branch names concise and meaningful.
5. Apply this convention to all newly created branches.
6. Do not rename existing branches associated with
   open pull requests.
7. Do not rename historical merged branches.
8. Do not force-push solely to change branch naming.
9. Preserve existing repository security and
   branch-protection requirements.
10. Do not falsify Git authorship or remove attribution
    required by repository policy.
