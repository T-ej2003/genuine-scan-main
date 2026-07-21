# Session B B03 implementation evidence

This directory covers exactly the 20 workflows assigned to `b-03-workers-scheduled-outbox-delivery`.

The application boundaries are implemented behind explicit activation gates, but none of these workflows is described as locally certified yet. Session A still owns the required Prisma columns/migrations, `app_rls` functions and grants, runtime-role provisioning, A-owned compliance scheduler seam, global SQL generation, and PostgreSQL 18 integration certification. Enabling either B03 gate before those requests are complete fails closed.

Focused tests prove the exact workflow registry, static function signatures, bounded inputs, payload-digest rejection, trusted database-role check, job-family separation, and transaction context ordering. Session B's fresh PostgreSQL 18 probe gate runs now in the dedicated `mscqr_rls_wave_b_auth_public_workers` database and proves these local boundary primitives. Session A still owns later production-function/schema integration and global certification.
