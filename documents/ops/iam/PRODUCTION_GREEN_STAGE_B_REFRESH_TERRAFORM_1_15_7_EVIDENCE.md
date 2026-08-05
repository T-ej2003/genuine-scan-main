# Stage B Terraform 1.15.7 refresh evidence

The sanitized fixture `scripts/tests/fixtures/production-green-stage-b-refresh-terraform-1.15.7.json`
is derived from the preserved `terraform show -json` output produced by Terraform 1.15.7
for protected SHA `25d9474437183db4c8c85e420b960558bf12da53`.

Source evidence SHA256: `5d35e33fc2ebd1501361dc31eeaaf766b7eaf22f95cd5a277da083e56648c364`.

The pinned Terraform output contains eight `check.*` entries and two reviewed
`var.*` validation entries. Each top-level and instance status is `pass`. Terraform
renders addresses as objects with `to_display`; the refresh contract accepts that
canonical shape and still rejects unknown, duplicate, missing, or malformed inventory.
