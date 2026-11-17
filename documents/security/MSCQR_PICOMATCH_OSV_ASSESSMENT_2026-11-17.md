# PR #854 picomatch audit assessment — 17 November 2026

## Observed failure and baseline

Deployment Audit runs `44144815133` and `44175097735` failed at `scripts/check-osv-runtime.mjs` after OSV reported `GHSA-fc5q-39xc-vjpf` / `CVE-2026-112366` for `picomatch` 2.3.2, 4.0.4, and 4.0.7. The old gate classified these lockfile entries as `UNKNOWN: executable provenance incomplete`; that was a reachability classification, not a finding that the advisory was false. GitHub's reviewed advisory describes a regular-expression denial of service when a caller supplies a crafted repeated extglob pattern.

Protected main `892cea9cc590b4a01bfd64bc9ea82f73a4321612` and the failing PR head had identical package manifests, lockfiles, OSV policy script, and audit workflow blobs. Main audit run `44062388326` passed earlier on 17 November with OSV Scanner 2.6.0 and zero accepted findings; the later PR audit used the same scanner version and failed with the same locked dependency versions. The advisory result changed after that baseline run; an earlier passing audit does not override the current finding.

## Dependency and execution paths

`npm explain picomatch` and `npm ls --omit=dev picomatch --all --json` were run for both package roots. Every reported instance is in a development dependency path:

| Lockfile | Version | Paths into the package |
| --- | --- | --- |
| root | 2.3.2 | Tailwind CSS → chokidar → anymatch/readdirp; Tailwind CSS/fast-glob → micromatch |
| root | 4.0.4 | Vitest; Tailwind CSS/Vite/Vitest/ESLint → tinyglobby |
| root | 4.0.7 | Vite |
| backend | 4.0.4 | `@yao-pkg/pkg` and its tinyglobby dependency |

The frontend image copies built static assets into nginx, not its builder `node_modules`. The backend Dockerfile prunes development dependencies before copying `node_modules`. A source search found no application import of `picomatch`, `micromatch`, `anymatch`, or `tinyglobby`, and no route supplying attacker-controlled glob patterns to them. A fresh build nevertheless found a separate `picomatch@4.0.4` inside **global npm in the final backend image**, despite the pruned application tree. The Node base image carried the same global npm dependency. The startup wrapper used `npm run start` and `npx prisma migrate deploy`; the candidate invokes their installed Node and Prisma entrypoints directly and removes global npm from both Node production targets. Fresh local backend/worker, database-executor, and static frontend image builds then found no `picomatch` package directory. No deployed image was inspected. The connector packaging artifact requires separate review when a new connector is built.

## Upstream state and remediation

As checked on 17 November 2026, the [GitHub advisory](https://github.com/advisories/GHSA-fc5q-39xc-vjpf) marks versions through 4.0.7 affected and lists **no patched version**. The [upstream release list](https://github.com/micromatch/picomatch/releases) and npm registry both list 4.0.7 as latest. Updating within the current published range cannot remove this advisory. Package manifests and lockfiles remain unchanged.

The corrected gate classifies a vulnerable development dependency as non-runtime only when its exact locked copies have `dev: true` and integrity hashes, three freshly built final images exclude the package, a fresh browser module census excludes it, and a second browser build remains byte-identical after every installed JavaScript source file of the package is instrumented in a fresh process. The package files are restored in `finally`. The unfiltered OSV findings remain visible in audit output and evidence. Tests reject runtime graphs, missing proof, positive browser modules, plugin code copying, and incomplete scanner evidence. The exact gate passed locally against the downloaded failing CI OSV report with only source paths adapted to the local checkout; the new PR-head CI result must still be checked.

Mitigation options, in order of evidence needed:

1. Take an upstream patched release when available, update only the affected dependency paths, rebuild, and rerun OSV plus printing regression tests.
2. If a patch remains unavailable, separately review and test a maintained replacement or audited fork with the vulnerable parser corrected. This requires a dedicated dependency change and artifact provenance check.
3. Keep build inputs and glob configuration source-controlled; do not feed manufacturer or public request data into build-time glob tooling. Verify deployed image contents and connector artifacts before claiming runtime non-reachability.

Do not suppress the advisory, relabel unknown reachability as safe, or disable the OSV gate to obtain a green PR. Deployment Audit remains a merge blocker until the new head passes required CI.
