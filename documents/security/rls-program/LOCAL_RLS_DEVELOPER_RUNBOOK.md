# Local RLS developer runbook

`scripts/rls/lib/workflow-delegation-registry.mjs` separates an implementation source from the canonical workflow owner. A controller may own an HTTP workflow while a transaction-only repository performs its database call; the generated manifest keeps both the controller source and repository access evidence.

The reviewed inventory baseline is 400 canonical workflows. This supersedes the historical 428-source snapshot after the Session B/C handoff: 28 legacy maintenance and seed TypeScript entrypoints are no longer registered runtime commands (several are now explicit refusing wrappers). The baseline remains fail-closed and is verified by the partition, package and manifest checks.

Add a delegation only when the source function is an implementation detail of one reviewed workflow. Use its stable execution surface, source file, and function as the delegated key; record the canonical surface, source file, function, and a short reason. The inventory validates duplicate keys, paths, functions, surfaces, self-delegation, and stable order. Never edit generated JSON: run the generator instead.

Run the static local gate:

```bash
npm run rls:integration-check
```

It writes secret-safe `summary.json`, `summary.md`, and `integration-check.log` to ignored `artifacts/rls-runs/<timestamp>/`. It makes no database mutation.

The local orchestration foundation defaults to static checks and accepts only local phases:

```bash
npm run rls:production-ready -- --phase repair
npm run rls:production-ready -- --phase static
npm run rls:production-ready -- --phase ephemeral
npm run rls:production-ready -- --phase all-local
```

`repair` regenerates deterministic local artefacts; `static` runs the permanent integration gate; `ephemeral` runs the existing disposable enforcement suite when its local dependency is available. Local success proves source inventory and local verification only. It does not certify staging, enable production RLS, or authorize activation; those remain separate future gates.

If a static run reports an unknown launch-blocked workflow, do not delete it from `essential-workflow-allowlist.json`. First add exact source/function attribution and reviewed named-function table-command evidence. Session B/C repositories must have their SQL function definitions in the reviewed package before their application workflow can be certified.
