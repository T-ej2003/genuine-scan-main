# Stage-B prerequisite bundle

PR #522 uses one canonical producer run to build the four immutable inputs required by the dedicated refresh-only state reconciler:

| Logical artifact | Archive filename |
| --- | --- |
| `broker-package` | `broker-package.zip` |
| `broker-package-manifest` | `broker-package.manifest.json` |
| `stage-a-handoff` | `stage-a-input.json` |
| `stage-a-state-backup` | `stage-a-state-backup.json` |

The producer is `.github/workflows/produce-production-green-stage-b-prerequisite-bundle.yml`. It obtains the Stage-A state through the credential-bound AWS runner, derives the Stage-A handoff and broker package from the checked-out source, and publishes one ZIP artifact. `prerequisite-manifest.json` binds all four payload hashes, sizes, canonical names, existing contract IDs, source SHA, ticket, repository, workflow path, run ID, run attempt, and artifact provenance.

Preparation and execution accept only the authenticated producer run and artifact identity. Execution downloads the producer artifact again, verifies the GitHub run and artifact digest, strictly extracts the exact archive, and materializes every file under a consumer-created `0700` directory with `0600` files. Runtime tfvars/binding are explicit derived artifacts; only the exact broker path in tfvars and the four canonical prerequisite path fields in the binding may change.

The bundle is a private transport contract for this reconciliation. It is not a generic artifact framework and it does not authorize production execution or remote-resource mutation.
