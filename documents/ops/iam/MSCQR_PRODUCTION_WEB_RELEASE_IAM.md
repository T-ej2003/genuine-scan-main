# Production web release IAM

This isolated root defines the GitHub OIDC web-image publisher and the exact frontend activation capability on the existing production release-deployer. It does not publish or deploy anything.

The publisher can write only `mscqr-web`; its permissions boundary is identical to its inline policy. AWS does not support resource-level authorization for `ecs:RegisterTaskDefinition`, so that API necessarily uses `Resource: "*"`. Registration safety instead comes from the isolated release-deployer, source-controlled constructor, exact two-role `iam:PassRole`, complete readback, and exact frontend-service CAS. The role can update only `mscqr-frontend-servi-euw2` and read only `mscqr-web` image metadata.

Validation is non-mutating:

```sh
terraform fmt -check
terraform init -backend=false
terraform validate
```

Any future apply requires the repository's separate governed IAM/Terraform authorization. This root is not an application release mechanism.
