# Main Branch Protection Checklist

Use this checklist to confirm GitHub is enforcing release-critical checks before merging to `main`.

## Required checks

- `Release Candidate Gate / rc-trust-critical`
- `Release Candidate Gate / rc-staging-smoke`

## Click-by-click (GitHub UI)

1. Open repository settings.
2. Go to **Rules** (or **Branches** if classic branch protection is enabled).
3. Ensure there is an active rule/ruleset targeting `main`.
4. Enable:
   - Require pull request before merging.
   - Require status checks to pass.
5. Add the two required checks above exactly by name.
6. Save and confirm the rule is **Active**.

## CLI/API verification

Run this from repo root:

```bash
GITHUB_REPOSITORY=<owner/repo> \
GITHUB_TOKEN=<token-with-repo-admin-read> \
RELEASE_PROTECTED_BRANCH=main \
node scripts/check-release-governance.mjs
```

Expected result JSON includes:

- `missing: []`
- `configuredChecks` contains both RC checks.

If `missing` is non-empty, treat as a release blocker.

