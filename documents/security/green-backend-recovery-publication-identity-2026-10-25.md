# Green backend recovery publication identity failure

Release Gate run `40240522175` failed while authenticating the image evidence in the normal-deployer execution job. The root-signed publication identity carried SHA-256 `c1856d35f85e73af0b5b251d9a90bf3b61c9d9193bb06c135c666a70139bac97`. The existing S3 recovery journal sorted its object keys, so the old order-sensitive hash function calculated `954196437c9dc592f605b85db371009d0c006be8ab2283d1a628e779cf2f7c01` for the same identity. The canonical signed report and identity values were unchanged.

The correction validates the identity's exact field set and reconstructs the producer's field order before calculating its historical signed hash. It leaves the signature, source, digest, and authorization checks intact. Regression coverage authenticates the signed report after the existing journal serialization and rejects tampering and added fields.

The failed transaction registered task definition `mscqr-production-rls-green-backend-candidate:36`. Its S3 journal has a completed registration receipt and no `BACKEND:UPDATE` claim or completion. The service remained on task definition `:24` with desired 2, running 0, and component-state generation 1 at reconciliation. The registered revision must be reconciled through the governed contract; the denied older dispatch must not be replayed.

After this correction is merged, recovery requires a new exact-main authorization assessment, a fresh six-domain database verdict, a current operator approval and protected environment approvals. Native ECS and journal readbacks must precede any new mutation. This source correction does not authorize a production dispatch.
