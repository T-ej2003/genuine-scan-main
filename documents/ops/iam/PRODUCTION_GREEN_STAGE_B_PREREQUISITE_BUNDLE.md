# Stage-B prerequisite bundle

One canonical producer run builds the six immutable inputs required by the dedicated refresh-only state reconciler:

| Logical artifact | Archive filename |
| --- | --- |
| `broker-package` | `broker-package.zip` |
| `broker-package-manifest` | `broker-package.zip.manifest.json` |
| `stage-a-handoff` | `stage-a-input.json` |
| `stage-a-state-backup` | `stage-a-state-backup.json` |
| `stage-b-tfvars` | `stage-b.tfvars` |
| `stage-b-tfvars-binding` | `stage-b-tfvars-binding.json` |

The producer is `.github/workflows/produce-production-green-stage-b-prerequisite-bundle.yml`. It authenticates the exact source-bound image-authorization artifact, obtains the Stage-A and Stage-B states through credential-bound readers, derives the Stage-A handoff, broker package, canonical `stage-b.tfvars`, and its binding report from the checked-out source, and publishes one ZIP artifact. `prerequisite-manifest.json` binds all six payload hashes, sizes, canonical names, existing contract IDs, source SHA, ticket, repository, workflow path, run ID, run attempt, and artifact provenance.

Preparation and execution accept only the authenticated producer run and artifact identity. Execution downloads the producer artifact again, verifies the GitHub run and artifact digest, strictly extracts the exact archive, and materializes every file under a consumer-created `0700` directory with `0600` files. Runtime tfvars/binding are explicit derived artifacts; only the exact broker path in tfvars and the four canonical prerequisite path fields in the binding may change.

The original tfvars and binding are authenticated from the prerequisite artifact and checked for their immutable semantic identity without dereferencing producer-runner paths. After all prerequisites are materialized, the derived runtime tfvars and binding retain the canonical `stage-b.tfvars` basename and are checked with the full prerequisite-file validation. This ordering permits producer and consumer runners to differ while keeping the original hashes and the relocated file hashes authenticated.

## Governed producer/consumer chain

| Producer | Output and binding | Consumer and validation | Required provenance |
| --- | --- | --- | --- |
| Image-authorization workflow | `image-authorization.json`; source, publication, evidence and signature digests | Prerequisite producer; `verifyProductionReleaseImageAuthorization` | Repository, protected source SHA, workflow path, run, attempt, artifact ID/name/digest |
| Prerequisite producer | `broker-package.zip` and `broker-package.zip.manifest.json`; raw/archive/tree/contract digests | `generateStageBTfvars`; `assertStageBBrokerPackageManifest` | Checked-out source and derived tooling tree |
| Prerequisite producer | `stage-b.tfvars` and `stage-b-tfvars-binding.json`; canonical basename and all prerequisite hashes | Bundle creator; `assertStageBTfvarsBinding` | Source SHA, image authorization, Stage-A and Stage-B state identities |
| Bundle creator | `prerequisite-bundle.zip`; exact six-member manifest and member digests | Preparation and execution workflows; `assertStageBPrerequisiteBundle` | Repository, producer workflow, run, attempt, source SHA, ticket, artifact ID/digest |
| Runtime materializer | Private relocated prerequisites plus canonical `stage-b.tfvars`; relocation-contract digest | Preparation CLI; full binding validation | Authenticated bundle bytes; no caller-selected output path |
| Preparation CLI | Refresh-only saved plan and preparation JSON; exact ten-address census, plan SHA and state pre-image | Authorization workflow | Backend/workspace identity, source SHA, state lineage/serial, zero remote mutations |
| Authorization workflow | Authorization JSON | Execution workflow; `assertStageBStateReconciliationAuthorization` | Protected-environment reviewer, preparation digest, freshness, run attempt |
| Execution workflow | Exact saved-plan state write and result JSON | Post-write verification | Reauthenticated prerequisite/preparation/authorization artifacts, state CAS, saved-plan bytes |
| Post-write verification | Clean refresh-only and ordinary plans | Ordinary Stage-B broker/runtime convergence and schema-2 approval flow | Same protected source, backend state and canonical tfvars contract |

The canonical `produce-production-green-stage-b-state-reconciliation-image-authorization.yml` workflow publishes `production-green-stage-b-state-reconciliation-image-authorization`. Supply its exact successful run ID (attempt `1`), artifact ID, and artifact digest to the prerequisite producer. After that artifact produces the bound tfvars and binding, supply their hashes to `produce-production-green-stage-b-release-preflight.yml`. The preparation workflow accepts only compact run, attempt, artifact, and digest inputs; it independently downloads and authenticates the prerequisite and preflight artifacts and never transports tfvars or binding contents through `workflow_dispatch`.

The approved relocation identity is path-independent. It binds the original tfvars and binding hashes, prerequisite-manifest hash, the exact four-field allowlist, each field-to-logical-artifact mapping, canonical filename, artifact hash, and non-path tfvars/binding identity. Each phase still hashes its own runtime tfvars, runtime binding, and physical materialization for local integrity; those runner-specific hashes are not compared across jobs. This permits preparation and execution to use different private roots without weakening prerequisite or saved-plan authentication.

The bundle is a private transport contract for this reconciliation. It is not a generic artifact framework and it does not authorize production execution or remote-resource mutation.
