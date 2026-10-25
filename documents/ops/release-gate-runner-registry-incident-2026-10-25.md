# Release Gate runner image source, 2026-10-25

Backend recovery run `40155154553` failed twice before any deployment step. Both attempts stopped while GitHub initialized the PostgreSQL service container: public ECR returned `Data limit exceeded` for the pinned digest. The backend ECS service remained on task definition `:24` with desired 2 and running 0; no recovery journal artifact was produced.

Release Gate now pulls its PostgreSQL and Redis service containers from Docker Hub using the same immutable digests already used by the repository's quality and auth security workflows. This changes the runner's registry endpoint, not the database or cache images, production task definition, recovery authorization, or AWS deployment code. The protected environment and native recovery journal requirements still apply.

After merge, use the new protected-main SHA for recovery. Reauthenticate image authorization and the read-only database verdict against that source and image. Do not redispatch the failed run against an ambiguous native result; its two attempts failed at runner initialization, before any AWS mutation step.
