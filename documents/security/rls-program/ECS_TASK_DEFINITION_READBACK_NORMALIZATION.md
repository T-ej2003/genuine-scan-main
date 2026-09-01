# ECS task-definition readback normalization

This matrix governs the shared semantic comparator at
`infra/aws/terraform/lambda/production-rls-approval-broker/ecs-task-definition-readback.mjs`.
It is deliberately a field allowlist, not a recursive removal of `false`, `0`,
empty arrays, or empty objects. The inputs are the Stage-B Terraform task
definition resources and JSON templates, the ECS API references for
`TaskDefinition`, `ContainerDefinition`, and `DescribeTaskDefinition`, and the
sanitized production-shaped backend fixture plus the captured ECS response in
`documents/ops/evidence/aws-elasticache-rightsize-inventory-20260603T184059Z/07-ecs-services-and-taskdefs.txt`.

`EXACT` means the value is included in the semantic comparison. `AWS_METADATA`
is stripped from the semantic payload but the readback caller separately binds
the exact ARN, family, revision and `ACTIVE` status. `NOT_REACHABLE` means the
current MSCQR Stage-B Terraform/templates do not set it; a materialized
non-empty or non-default value is therefore still rejected by exact comparison.

## Top-level task definition fields

| Field | Expected registration shape | Readback/default evidence | Classification | Normalization | Security effect if non-default |
| --- | --- | --- | --- | --- | --- |
| `family` | Terraform/template value | exact API response | EXACT | none | selects executable family |
| `taskRoleArn` | Terraform role | exact API response | EXACT | none | container AWS authority |
| `executionRoleArn` | Terraform role | exact API response | EXACT | none | image/log/secret retrieval authority |
| `networkMode` | `awsvpc` | exact API response | EXACT | none | task network isolation |
| `containerDefinitions` | template JSON | exact API response subject to container rows below | EXACT | field-specific child rules only | executable payload |
| `volumes` | omitted or explicit reviewed volume list | capture materializes `[]` when absent | AWS_BENIGN_EMPTY | `[]` to omission only | non-empty volumes remain exact |
| `placementConstraints` | omitted for Fargate | capture materializes `[]` | AWS_BENIGN_EMPTY | `[]` to omission only | non-empty constraints remain exact |
| `requiresCompatibilities` | `FARGATE` | exact API response | EXACT | none | launch type |
| `cpu` | reviewed Fargate task size | exact API response | EXACT | none | task capacity |
| `memory` | reviewed Fargate task size | exact API response | EXACT | none | task capacity |
| `runtimePlatform` | Terraform-fixed `LINUX`/`X86_64` | exact API response | EXACT | none | OS/architecture |
| `enableFaultInjection` | omitted | ECS documents default `false`; capture has `false` | AWS_BENIGN_DEFAULT | `false` to omission only | `true` remains exact and enables fault injection |
| `ephemeralStorage` | not set | no MSCQR materialization evidence | NOT_REACHABLE | none | storage capacity |
| `proxyConfiguration` | not set | no MSCQR materialization evidence | NOT_REACHABLE | none | proxy/network behavior |
| `ipcMode` | not set | no MSCQR materialization evidence | NOT_REACHABLE | none | IPC namespace exposure |
| `pidMode` | not set | no MSCQR materialization evidence | NOT_REACHABLE | none | process namespace exposure |
| `inferenceAccelerators` | not set | no MSCQR materialization evidence | NOT_REACHABLE | none | accelerator attachment |
| `taskDefinitionArn` | AWS-generated | Describe response | AWS_METADATA | strip; caller binds exact ARN | immutable revision identity |
| `revision` | AWS-generated | Describe response | AWS_METADATA | strip; caller binds exact revision | immutable revision identity |
| `status` | AWS-generated | Describe response | AWS_METADATA | strip; caller requires `ACTIVE` | runnable state |
| `registeredAt` | AWS-generated | Describe response/capture | AWS_METADATA | strip | audit timestamp |
| `registeredBy` | AWS-generated | Describe response/capture | AWS_METADATA | strip | audit identity |
| `deregisteredAt` | AWS-generated | Describe response schema | AWS_METADATA | strip | lifecycle timestamp |
| `deleteRequestedAt` | AWS-generated | Describe response schema | AWS_METADATA | strip | lifecycle timestamp |
| `compatibilities` | ECS-derived | Describe response/capture | AWS_METADATA | strip | derived validation result |
| `requiresAttributes` | ECS-derived | Describe response/capture | AWS_METADATA | strip | derived placement attributes |
| `tags` | response metadata when requested | Describe response | AWS_METADATA | strip from semantic payload | separately verified where a creation marker is required |

## Container-definition fields

| Field | Expected registration shape | Readback/default evidence | Classification | Normalization | Security effect if non-default |
| --- | --- | --- | --- | --- | --- |
| `name` | template value | exact API response | EXACT | none | container identity |
| `image` | immutable digest | exact API response | EXACT | none | executable image |
| `repositoryCredentials` | not set | no MSCQR materialization evidence | NOT_REACHABLE | none | registry credentials |
| `cpu` | omitted in MSCQR containers | ECS CPU contract and capture materialize `0` | AWS_BENIGN_DEFAULT | omission to `0` | non-zero remains exact |
| `memory` | not set | no MSCQR materialization evidence | NOT_REACHABLE | none | container limit |
| `memoryReservation` | not set | no MSCQR materialization evidence | NOT_REACHABLE | none | container reservation |
| `links` | not set | no MSCQR materialization evidence | NOT_REACHABLE | none | container connectivity |
| `portMappings` | omitted or reviewed mapping | capture/readback can materialize `[]` | AWS_BENIGN_EMPTY | `[]` to omission only | non-empty mappings remain exact |
| `essential` | explicit `true` | exact API response | EXACT | none | task failure behavior |
| `restartPolicy` | not set | no MSCQR materialization evidence | NOT_REACHABLE | none | restart behavior |
| `entryPoint` | reviewed array | exact API response | EXACT | none | executable entrypoint |
| `command` | omitted or reviewed array | exact API response | EXACT | none | executable command |
| `environment` | reviewed values, except read-only canary omission | ECS Describe sample materializes `[]` | AWS_BENIGN_EMPTY | `[]` to omission only | non-empty values remain exact |
| `environmentFiles` | omitted | capture materializes `[]` | AWS_BENIGN_EMPTY | `[]` to omission only | non-empty files remain exact |
| `mountPoints` | omitted or reviewed mounts | capture materializes `[]` | AWS_BENIGN_EMPTY | `[]` to omission only | non-empty mounts remain exact |
| `volumesFrom` | omitted | capture materializes `[]` | AWS_BENIGN_EMPTY | `[]` to omission only | non-empty mounts remain exact |
| `linuxParameters` | reviewed only for rotation backend | exact API response | EXACT | none | kernel/process behavior |
| `secrets` | reviewed secret references | exact API response | SECURITY_RELEVANT | none | runtime secret access |
| `dependsOn` | not set | no MSCQR materialization evidence | NOT_REACHABLE | none | start ordering |
| `startTimeout` | not set | no MSCQR materialization evidence | NOT_REACHABLE | none | start behavior |
| `stopTimeout` | not set | no MSCQR materialization evidence | NOT_REACHABLE | none | shutdown behavior |
| `hostname` | not set | no MSCQR materialization evidence | NOT_REACHABLE | none | network identity |
| `user` | not set | no MSCQR materialization evidence | NOT_REACHABLE | none | process privilege |
| `workingDirectory` | not set | no MSCQR materialization evidence | NOT_REACHABLE | none | executable path context |
| `disableNetworking` | not set | no MSCQR materialization evidence | NOT_REACHABLE | none | network access |
| `privileged` | explicit `false` | exact API response | SECURITY_RELEVANT | none | host privilege boundary |
| `readonlyRootFilesystem` | explicit `true` | exact API response | SECURITY_RELEVANT | none | filesystem mutation boundary |
| `dnsServers` | not set | no MSCQR materialization evidence | NOT_REACHABLE | none | name resolution |
| `dnsSearchDomains` | not set | no MSCQR materialization evidence | NOT_REACHABLE | none | name resolution |
| `extraHosts` | not set | no MSCQR materialization evidence | NOT_REACHABLE | none | host routing |
| `dockerSecurityOptions` | not set | no MSCQR materialization evidence | NOT_REACHABLE | none | container security options |
| `interactive` | explicit `false` | exact API response | SECURITY_RELEVANT | none | interactive execution |
| `pseudoTerminal` | explicit `false` | exact API response | SECURITY_RELEVANT | none | terminal allocation |
| `dockerLabels` | not set | no MSCQR materialization evidence | NOT_REACHABLE | none | container metadata consumed by tooling |
| `ulimits` | omitted | capture materializes `[]` | AWS_BENIGN_EMPTY | `[]` to omission only | non-empty limits remain exact |
| `logConfiguration.logDriver` | `awslogs` | exact API response | SECURITY_RELEVANT | none | log delivery |
| `logConfiguration.options` | reviewed map | exact API response | SECURITY_RELEVANT | none | log destination/options |
| `logConfiguration.secretOptions` | omitted | capture materializes `[]` | AWS_BENIGN_EMPTY | `[]` to omission only | non-empty name/value references remain exact and ordered |
| `healthCheck` | not set in current Stage-B templates | no MSCQR materialization evidence | NOT_REACHABLE | none | task health semantics |
| `systemControls` | omitted | capture materializes `[]` | AWS_BENIGN_EMPTY | `[]` to omission only | non-empty kernel settings remain exact |
| `resourceRequirements` | not set | no MSCQR materialization evidence | NOT_REACHABLE | none | device/GPU allocation |
| `firelensConfiguration` | not set | no MSCQR materialization evidence | NOT_REACHABLE | none | log routing |
| `credentialSpecs` | not set | no MSCQR materialization evidence | NOT_REACHABLE | none | Windows credential behavior |
| `versionConsistency` | not set | no MSCQR materialization evidence | NOT_REACHABLE | none | image resolution behavior |

The regression suite injects each `AWS_BENIGN_DEFAULT` and
`AWS_BENIGN_EMPTY` representation one field at a time. It also proves that a
non-default fault-injection value, non-empty log secret option, changed role,
image, command, environment, secret, network mode, or runtime platform remains
a mismatch. Array ordering is preserved by the canonical serializer.
