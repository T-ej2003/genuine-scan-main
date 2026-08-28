# Production dual-slot runtime trust

The runtime bootstrap accepts a dual-slot binding only after its origin is
independently authenticated. The initial path verifies the live initial
seven-slot resources; the rebaseline path verifies the protected authorization
and fresh live post-write seven-slot state. The manifest's `kind` and
`producer` are schema assertions, not authority, and there is no validator
fallback between origins.

Rebaseline authorization evidence is produced only after the protected
production environment gate. The workflow obtains the actual approved
environment user from GitHub's run-approval evidence; dispatcher inputs are not
used as reviewer authority. Runtime preparation resolves and authenticates that
authorization while the GitHub control-plane credential is available, then
embeds the authenticated evidence into the hash-bound runtime configuration.
The later AWS/Terraform/ECS execution environment intentionally contains no
GitHub credential and performs no late GitHub lookup.

This change is source/test-only. It does not dispatch workflows or perform
production mutations.
