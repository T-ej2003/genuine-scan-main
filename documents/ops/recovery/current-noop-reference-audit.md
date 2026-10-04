# Current broker references in a converged Stage B plan

## Failure and correction

After the authorized infrastructure convergence, a fresh read-only plan correctly
reported no changes. The reference generator nevertheless copied each current
no-op task definition into its atomic-rollover map with `oldArn = currentArn`.
It then treated the live current reference as superseded and demanded a Lambda
update. The production-shaped local fixture reproduced that failure before the
source correction.

The shared broker-mode validator now distinguishes an authenticated current no-op
reference from a stale reference requiring a transition. The pass branch requires:

- exactly one current task-definition change, revalidated by the existing immutable
  no-op/source/image/planned-value contract;
- exactly one broker change whose action is no-op;
- a complete, known broker environment in both before and after observations;
- both planned task-definition maps equal the authenticated live broker map.

A no-op action alone grants no authority. No broker version, release SHA, worker
family or incident-specific exception is added. Stale references still use the
existing exact planned replacement and atomic-broker-update validation. Unknown
references, incompatible maps, duplicate changes, unknown target values and stale
source/image content fail closed. Broker updates remain governed by the existing
update contract; this correction does not introduce redundant update authority.

## Validation and hostile review

The new tests cover the converged twelve-definition plan and plan/audit binding,
stale references in all nine broker modes, unknown revisions, conflicting before
and after targets, duplicate broker/definition changes, changed planned ARN,
missing/malformed/unknown maps, ambiguous environments and stale source content.
Existing exact-replacement, bootstrap-forward, retained-worker and additional
unknown-worker regressions remain part of the validation suite.

Local validation: 233/233 focused reference tests; 966/966 Stage B control-plane
tests; 108/108 historical-runtime tests; 17/17 closure tests; 139/139
state/approval/normal-deployment tests; 21/21 workflow contracts; 95 valid workflow
YAML files; capability graph and dependency closure with zero violations. Static
pull-request closure validation also passes. Hostile self-review found no remaining
actionable issue.

Workflow and capability checks are unchanged. No infrastructure apply, AWS call,
worker lifecycle, printing, RLS, IAM, dependency or MFA change is part of this PR.

## Recovery ordering and checker authentication

Merge only after exact-head independent review and required CI are green. Then
update protected main and rerun fresh canonical Full-RLS preparation, refreshing
expired evidence through existing producers. Do not reapply the completed
infrastructure transaction. Any new plan remains separately governed.

Only after preparation is otherwise ready should the human execute the existing
checker authentication path in their own interactive terminal:

```sh
aws sts get-caller-identity --profile mscqr-production-rls-independent-checker --region eu-west-2 --output json --no-cli-pager
```

The documented chain is checker operator -> MFA-backed
`mscqr-production-independent-checker` ->
`mscqr-production-rls-independent-checker`. Preserve its trust and role boundaries.
Enter MFA only at the terminal prompt; never paste it into chat or store it in
files/logs. The approval-input producer consumes the resulting short-lived
inherited checker session through the existing credential contract. No checker
authentication attempt was made during this code correction.

Recommendation: finish this narrow review/merge, then resume fresh preparation and
stop at the Full-RLS approval boundary. No new recovery mechanism is needed.
