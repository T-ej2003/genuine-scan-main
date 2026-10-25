# Release Gate resolver dependency failure — 25 October 2026

Backend health recovery run `40147993883` failed in **Resolve deploy target**, before the protected `production` environment and before AWS mutation. The lifecycle validator imported `js-yaml`, but the resolver job had not installed locked repository dependencies. The later deployment job did install them, so its setup could not help the resolver.

The correction installs the root lockfile's dependencies with package scripts disabled before target validation. The existing parsed-workflow test now asserts this ordering and executes the backend recovery lifecycle path. No deployment authorization, ECS mutation, or freshness check changes.

`release-gate.yml` is an input to the generated RLS source contract. The generated package was refreshed from source; policy counts, migration digest, and SQL behavior remain unchanged. The old recovery evidence is bound to source `c033eca952435a8d668d5f9c0fb6c2f2fa8b6b77` and cannot be relabeled for the merge commit. After merge, publish and authorize an image for the new protected main, obtain a fresh database compatibility verdict and operator ticket binding, then dispatch the governed recovery lane. Preserve the failed run as proof that it made no AWS mutation.
