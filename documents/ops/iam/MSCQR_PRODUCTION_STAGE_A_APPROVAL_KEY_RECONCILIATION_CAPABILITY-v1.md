# Production Stage-A approval-key reconciliation capability

This is the only governed local execution path for an approved Stage-A reconciliation of `aws_kms_key.approval`.

It accepts an authorization artifact only through its exact successful protected-environment workflow run and attempt. The artifact binds the protected source, saved and rendered plan hashes, Stage-A state identity, approval-key ARN, and before/after policy hashes.

The release-deployer remains without `kms:PutKeyPolicy` in steady state. The executor requires distinct root and release-deployer profiles. Root temporarily makes one managed-policy version the default with exactly:

```json
{
  "Effect": "Allow",
  "Action": "kms:PutKeyPolicy",
  "Resource": "arn:aws:kms:eu-west-2:368992683803:key/437cdebd-95e7-4aba-8f0f-2ca08edb0478"
}
```

Before the Terraform apply, the executor rechecks source, clean protected checkout, authorization artifact provenance, plan bytes and semantics, Stage-A state, and approval-key policy. It permits one apply of the executor-owned saved-plan copy.

The authorization-only workflow authenticates the requested checkout against the GitHub API's protected `main` identity before `npm ci` or any repository Node program runs. It hashes every tracked protected-source input before dependency installation and requires both a clean tracked worktree and identical hashes afterward.

The capability lifecycle treats every CreatePolicyVersion, default-version restoration, and temporary-version deletion attempt as unknown until bounded, delayed IAM topology convergence authenticates the resulting state. Recovery locates the temporary version by the exact capability policy document, never by a predicted or response-only version ID. Creation must be positively observed as the default policy before Terraform is reachable; restoration and deletion each require two consecutive delayed observations of the security-relevant topology. Terraform is unreachable while capability state is unknown.

Cleanup runs after both success and failure: restore the prior managed-policy default version, verify it, delete the temporary non-default version, and verify the release-deployer is again denied `kms:PutKeyPolicy`. A cleanup authentication failure is `CRITICAL_TEMPORARY_CAPABILITY_CLEANUP_FAILURE`; no further production action may proceed.

If the IAM managed-policy version limit is full, the executor may remove only the oldest non-default version whose document is either the current steady policy or an authenticated historical steady policy. Unknown, temporary, default, and undated versions stop the operation before temporary capability creation.

The root-drop temporary capability is a separate contract and cannot authorize this operation.
