# Production green Stage B release activation

Stage B is intentionally not a Terraform planning root. It is the protected release workflow and broker sequence described in `scripts/aws/apply-production-full-rls-release.mjs`. It is unavailable until Stage A state outputs, the external protected release role, an independent checker, signed approval, immutable backend/worker/executor images, and approved canary-secret injection are present.

Stage B may create fixed executor and canary task definitions, attach only the reviewed task-start secret permissions, publish the reviewed broker alias, run mandatory green application canaries, and then perform the separately approved backend/worker cutover. It must not change the frontend task definition (`mscqr-frontend:20`) or switch traffic before canaries pass.
