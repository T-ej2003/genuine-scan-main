-- Nullable only for already-persisted legacy records; new writes are stamped by the canonical producer trigger.
ALTER TABLE "AuditLogOutbox" ADD COLUMN "authorityProvenance" JSONB;
