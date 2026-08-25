# Production AWS API semantics audit

This audit covers the production mutation and recovery paths relied on by PR
#376. It records whether correctness depends on complete enumeration or an
exact versioned runtime selector. It is source qualification only; no AWS call
or mutation was made.

## Pagination census

| Reachable call | Classification | Completeness contract |
| --- | --- | --- |
| Backend recovery and rollback `ecs list-tasks` | `EXPLICITLY_PAGINATED_BY_SOURCE` | Shared bounded AWS CLI paginator consumes opaque `NextToken`, rejects cycles, deduplicates, sorts, and describes all tasks in batches of 100. |
| Backend/Stage-B recovery `ecs list-task-definitions` | `EXPLICITLY_PAGINATED_BY_SOURCE` | Bounded CLI `--starting-token` census; every revision is described before classification. |
| Stage-B reference audit `ecs list-services` / `list-tasks` | `EXPLICITLY_PAGINATED_BY_SOURCE` | Bounded CLI paginator with canonical `NextToken` shape. |
| Normal activation, rotation, cutover and existing-task deployment `ecs list-tasks` | `AUTO_PAGINATED_BY_CLI` | No service pagination limit is supplied; AWS CLI returns the complete combined result before exact desired-count and task checks. |
| Runtime IAM `iam list-role-policies` / `list-attached-role-policies` | `AUTO_PAGINATED_BY_CLI` | No pagination controls; all returned policies are individually read and hashed. |
| Runtime image `ecr describe-images --image-ids imageDigest=...` | `PROVABLY_SINGLETON` | Exact repository and digest must resolve to one matching `ImageDetail`. |
| Runtime secret `secretsmanager describe-secret --secret-id ...` | `PROVABLY_SINGLETON` | Exact ARN read; version metadata is validated without reading secret material. |
| Runtime SSM `describe-parameters` with exact Name equality | `PROVABLY_SINGLETON` | Exactly one matching ARN and no continuation token; parameter version and metadata are bound. |
| KMS `describe-key` / `get-key-policy` and IAM get/simulation calls | `PROVABLY_SINGLETON` or `BOUNDED_BY_CONTRACT` | Exact key, policy, role, action and resource identities are required. |
| CloudTrail denial lookup | `AUTO_PAGINATED_BY_CLI` | Service page size is 50; CLI pagination remains enabled and the complete combined event set is inspected. |

No reachable preflight may treat a returned prefix as a complete task or
revision census. The explicit readers cap enumeration at 100 pages and 1,000
stopped tasks; overflow is an ambiguity and fails closed.

## Versioned runtime selectors

Secrets Manager `valueFrom` is parsed as the base ARN plus JSON key, version
stage and version ID. The authenticated metadata binds `DeletedDate`, KMS key
identity, canonical `VersionIdsToStages`, the complete bounded and paginated
`ListSecretVersionIds --include-deprecated` census, selector mode and resolved
version. `DescribeSecret.VersionIdsToStages` proves stage ownership; it is not
treated as proof that an unlabeled version does not exist. No secret value is
read. Pagination cycles, malformed pages and conflicting version records fail
closed.

Repeated task-definition references to the same secret remain distinct runtime
dependencies, including their source fields and selectors. Only the generated
IAM `Resource` array is deduplicated and sorted, so repeated references do not
broaden authority or create a false candidate rejection.

Default references require one `AWSCURRENT`; explicit stages and IDs must
exist; a combined stage and ID must resolve to the same version. Duplicate
stage ownership, malformed AWS metadata, deletion, or metadata drift fails
before ECS mutation. `SecretString` and `SecretBinary` are never requested.

SSM task-definition references are exact parameter ARNs. The metadata binds
the exact ARN, name, type, current parameter version, data type, tier and KMS
identity. ECR is already digest-selected; repository, registry and exact
`ImageDetail.imageDigest` are bound. KMS proof binds enabled key state, usage,
key ARN and supported key-policy authority. No reachable S3 object-version
selector is present in the current candidate grammar; environment files bind
an exact object ARN and any future version-selector form remains unclassified
and therefore fails closed.
