# Safety Model

This project separates evidence, analysis, and approval.

## Default Mode

Default commands are read-only and local-output only. The sample config does not call AWS. Real AWS collection is limited to `describe`, `list`, and `get` style APIs.

## Categories

| Category | Meaning | Default action |
| --- | --- | --- |
| unused deletion candidate | Evidence suggests a resource may be unused | Review only |
| used but oversized | Resource appears active but metrics suggest excess capacity | Review metrics |
| DR posture decision required | Resource supports resilience or failover | Keep until business decision |
| blocked by AWS valid-modification API | Orderable target exists but AWS does not approve modification | Do not modify |
| manual approval required | Stateful, production, ambiguous, or risky resource | Keep |

## Mutation Gate

This tool must not run delete, modify, stop, start, terminate, release, detach, create, put, update, or similar AWS operations. Any future project that generates change plans should output commands as disabled text only and require separate approval tooling.

## Rollback Gate

No cleanup recommendation is complete without:

- Resource ID or ARN.
- Owner and business purpose.
- Cost evidence.
- Backup or rollback evidence.
- Post-action verification plan.
- Manual approval record.
