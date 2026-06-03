# AWS RDS class downsize plan

## DB instance

`mscqr-prod-db`

## Current class

`db.t4g.medium`

## Target class

`db.t4g.small`

## Reason

14-day metrics show low CPU, low IOPS, and low connection count. Memory is the limiting signal, so the first reduction is to `db.t4g.small`, not `db.t4g.micro`.

## Safety

A manual snapshot was created before mutation.

## Mutation not done in this commit

The DB class change is intentionally separated from the validation and snapshot evidence.
