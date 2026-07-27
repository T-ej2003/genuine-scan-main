# Tenant-directory read release boundary

Release Fix 2 replaces direct Prisma reads for `GET /licensees`, `GET /licensees/:id`, and `GET /users` with two exact PostgreSQL projections.

## Authority

Only `SUPER_ADMIN`, `PLATFORM_SUPER_ADMIN`, `LICENSEE_ADMIN`, and `MANUFACTURER_ADMIN` may enter these routes. PostgreSQL verifies the opaque `aq_db_session` capability first and derives the live user, session, and scope. `LICENSEE_ADMIN` is restricted to its active licensee and organization. `MANUFACTURER_ADMIN` is restricted to currently linked, active licensees. Every selector only narrows this derived scope.

`ORG_ADMIN`, `MANUFACTURER`, `MANUFACTURER_USER`, operators, missing or invalid capabilities, inactive users, suspended licensees, and stale manufacturer links are denied.

For transport compatibility only, the external `GET /users?role=MANUFACTURER` filter is normalized by the controller to `MANUFACTURER_ADMIN` before SQL. Returned rows retain the canonical stored role. This alias never applies to actor authorization, sessions, policies, or capability claims.

## Boundaries

- `app_rls.read_licensee_directory(text,text,text,text,boolean)` serves list and detail projections. The detail flag avoids a duplicate authority function.
- `app_rls.read_user_directory(text,text,text,text,boolean,text,integer,integer)` returns the existing paginated user projection.

Both functions are owned by the existing `NOLOGIN`, non-`BYPASSRLS` authentication function owner. PUBLIC execution is revoked; only the exact authenticated application role receives execution. Runtime roles retain no direct table access.

## Table access

The owner receives SELECT-only column privileges required by the projections on `User`, `Licensee`, `Organization`, `ManufacturerLicenseeLink`, `Invite`, `Batch`, `QRCode`, and `QRRange`. Policies are operation-specific and require the verified session binding. `QRRange` receives only this tenant-directory SELECT path—no INSERT, UPDATE, DELETE, or generic tenant policy.

## Rollback and proof

The Session A rollback drops the two exact signatures. Static tests seal the caller roles, signatures, grants, policies, and absence of direct Prisma reads. The focused PostgreSQL 18 probe covers same-scope success, cross-scope and role denial, capability failure, direct-table denial, FORCE RLS, ownership, and exact grants.
