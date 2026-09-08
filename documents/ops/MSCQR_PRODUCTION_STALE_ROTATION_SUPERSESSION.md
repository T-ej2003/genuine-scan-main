# Production stale-rotation supersession

Stale-rotation supersession is a two-phase production transaction. Omitting `--mode` fails closed.

## Prepare

Run `npm run stage-b:supersede-stale-rotation -- --mode prepare ...` from a clean protected-main checkout. Preparation authenticates the release-deployer identity, live ECS baseline, publication and Stage-B identities, then performs the existing ten version-pinned selector reads. It creates one private material journal under the fixed operator-owned `~/.mscqr/production-cutover/stale-rotation-supersession/<source>/<stale-rotation>/` directory and emits a sanitized seven-write preparation artifact. It performs no `PutSecretValue` operation.

Dispatch `authorize-production-stale-rotation-supersession.yml` with the exact preparation bytes and file SHA-256. The protected `production` environment supplies the independent approval; the workflow produces the only authorization accepted by execution.

## Execute

Run the same CLI with `--mode execute`, the exact preparation file SHA-256, and the authorization artifact. Execution reauthenticates protected main, the live task definition, all source versions and the canonical material journal before calling the shared write boundary. No secret write can occur until the approved artifact matches the preparation, publication, journal and ordered seven-write plan.

Each write retains the existing deterministic `ClientRequestToken`. An interrupted run may continue only an authenticated prefix of the same approved plan. The private material journal remains through initial dual-slot bootstrap, so a crash after write seven can finish that handoff without another write. Bootstrap then writes an authorization-bound consumption receipt and deletes the journal. A non-prefix state fails closed, and a completed transition rejects replay. The AWS version topology is the durable, caller-path-independent progress record; the fixed-path receipt records which authorization was consumed.

All ECS and Secrets Manager operations use the canonical sanitized release-deployer named-profile runner. Secret payloads reach `PutSecretValue` through stdin, never process arguments.

Never put the private material journal, secret payloads, or decoded secret values in GitHub inputs, artifacts, issues, logs, or source control.
