# MSCQR Production RLS Status Evidence

PostgreSQL Row-Level Security was checked from inside the ECS production VPC against the production RDS Proxy-backed database.

Result:

- RLS enabled: false on all public app tables
- RLS forced: false on all public app tables
- RLS policies: none found

Conclusion:

MSCQR production currently does not use PostgreSQL-native Row-Level Security. Tenant isolation is enforced at the backend application/service/Prisma authorization layer.

Operational warning:

Do not enable RLS directly in production without a full policy design, session tenant context, migration plan, and rollback plan.
