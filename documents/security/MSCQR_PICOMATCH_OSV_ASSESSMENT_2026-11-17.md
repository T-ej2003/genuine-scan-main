# PR #854 picomatch audit assessment — 17 November 2026

## Observed failure and baseline

Deployment Audit run `44144815133` fails at `scripts/check-osv-runtime.mjs` after OSV reports `GHSA-fc5q-39xc-vjpf` / `CVE-2026-112366` for `picomatch` 2.3.2, 4.0.4, and 4.0.7. The script classifies these lockfile entries as `UNKNOWN: executable provenance incomplete`; that is a reachability classification, not a finding that the advisory is false. GitHub's reviewed advisory describes a regular-expression denial of service when a caller supplies a crafted repeated extglob pattern.

Protected main `892cea9cc590b4a01bfd64bc9ea82f73a4321612` and PR #854 have identical `package.json`, `package-lock.json`, `backend/package.json`, `backend/package-lock.json`, OSV policy script, and audit workflow blobs. Main audit run `44062388326` passed earlier on 17 November with OSV Scanner 2.6.0 and zero accepted findings; the later PR audit used the same scanner version and failed with the same locked dependency versions. The changed advisory result is therefore a baseline dependency/security-feed issue, not a dependency introduced by this PR. An earlier passing audit does not override the current failure.

## Dependency and execution paths

`npm explain picomatch` and `npm ls --omit=dev picomatch --all --json` were run for both package roots. Every reported instance is in a development dependency path:

| Lockfile | Version | Paths into the package |
| --- | --- | --- |
| root | 2.3.2 | Tailwind CSS → chokidar → anymatch/readdirp; Tailwind CSS/fast-glob → micromatch |
| root | 4.0.4 | Vitest; Tailwind CSS/Vite/Vitest/ESLint → tinyglobby |
| root | 4.0.7 | Vite |
| backend | 4.0.4 | `@yao-pkg/pkg` and its tinyglobby dependency |

The root production frontend image copies built static assets into nginx, not its builder `node_modules`. The backend Dockerfile runs `npm prune --omit=dev` before copying `node_modules` to the runtime image. A source search found no direct `picomatch`, `micromatch`, `anymatch`, or `tinyglobby` import in application code, and no route passing request-supplied glob patterns to them. These are source and build-contract observations; no deployed image was inspected, and they do not prove that every build or connector-packaging invocation is unexploitable. The connector packaging dependency deserves separate artifact provenance review when a new connector is built.

## Upstream state and remediation

As checked on 17 November 2026, the [GitHub advisory](https://github.com/advisories/GHSA-fc5q-39xc-vjpf) marks versions through 4.0.7 affected and lists **no patched version**. The [upstream release list](https://github.com/micromatch/picomatch/releases) and npm registry both list 4.0.7 as latest. Updating within the current published range cannot remove this advisory. No lockfile or audit-policy change is proposed in PR #854.

Mitigation options, in order of evidence needed:

1. Take an upstream patched release when available, update only the affected dependency paths, rebuild, and rerun OSV plus printing regression tests.
2. If a patch remains unavailable, separately review and test a maintained replacement or audited fork with the vulnerable parser corrected. This requires a dedicated dependency change and artifact provenance check.
3. Keep build inputs and glob configuration source-controlled; do not feed manufacturer or public request data into build-time glob tooling. Verify deployed image contents and connector artifacts before claiming runtime non-reachability.

Do not suppress the advisory, relabel unknown reachability as safe, or disable the OSV gate to obtain a green PR. Until a supported remediation or separately approved security decision exists, Deployment Audit remains a merge blocker.
