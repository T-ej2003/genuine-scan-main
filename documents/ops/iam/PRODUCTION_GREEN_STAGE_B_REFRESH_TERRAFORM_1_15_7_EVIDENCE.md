# Stage B Terraform refresh evidence and version contract

The preserved production-shaped evidence was observed with Terraform `1.15.7`. That is
the exact version recorded and bound in the refresh evidence; it is not a global
production pin. The supported Stage B production constraint is `>= 1.6.0, < 2.0.0`,
from `infra/aws/terraform/production-green-stage-b/versions.tf`. Refresh validation
checks that range, preserves the observed version unchanged, and binds its exact value
through `terraformVersionSha256`.

The sanitized fixture `scripts/tests/fixtures/production-green-stage-b-refresh-terraform-1.15.7.json`
is derived from the preserved `terraform show -json` output produced by Terraform 1.15.7
for protected SHA `8882fcb5707b4bed3b95195f6eedc29e4dc870a6`.

Authoritative consumed production `terraform show -json` SHA256: `3d406c2caca132d27b00d211d4248dda50c8b6e7ac559ec1f9caf2912d45f4a5`.
The locally preserved structural capture used to derive the sanitized fixture is
`5d35e33fc2ebd1501361dc31eeaaf766b7eaf22f95cd5a277da083e56648c364`; the consumed
temporary plan directory was removed by the reviewed refresh entrypoint after report
publication.

The pinned Terraform output contains eight `check.*` entries and two reviewed
`var.*` validation entries. Each top-level and instance status is `pass`. Terraform
renders addresses as objects with `to_display`; the refresh contract accepts that
canonical shape and still rejects unknown, duplicate, missing, or malformed inventory.

Terraform 1.15.7 emits one instance per reviewed check in this fixture. Each instance is
a two-field object: `address: {to_display: <parent-address>}` and `status: "pass"`.
The `problems` field is omitted for passing instances and is optional only when absent;
if present it must be an array. The structured refresh evidence records 10 emitted and
10 passing instances, zero failed/malformed/duplicate instances, and a deterministic
instance-inventory SHA256 alongside the existing 8+2 check inventory proof.
