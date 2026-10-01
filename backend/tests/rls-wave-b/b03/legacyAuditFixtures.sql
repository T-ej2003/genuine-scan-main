-- Pre-correction serialized shapes. Loaded before installing the new trigger;
-- no production fixture, trigger disabling, or historical metadata fabrication.
INSERT INTO public."AuditLogOutbox"
(id,payload,"requestId","organizationId","licenseeId","initiatingUserId","expiresAt","updatedAt")
SELECT '00000000-0000-4000-8000-00000000'||n,
 '{"action":"LEGACY_RECOVERY","entityType":"Certification","entityId":"legacy","userId":"00000000-0000-4000-8000-000000000301","orgId":"00000000-0000-4000-8000-000000000101","licenseeId":"00000000-0000-4000-8000-000000000201"}'::jsonb,
 '00000000-0000-4000-8000-000000006101','00000000-0000-4000-8000-000000000101',
 '00000000-0000-4000-8000-000000000201','00000000-0000-4000-8000-000000000301',
 transaction_timestamp()+interval '1 day',transaction_timestamp()
FROM unnest(ARRAY['6101','6102']) n;
INSERT INTO public."AuditLogOutbox" (id,payload,"updatedAt")
VALUES ('00000000-0000-4000-8000-000000006103','{"action":"LEGACY_NO_AUTHORITY","entityType":"Certification"}',transaction_timestamp());
INSERT INTO public."AuditLogOutbox" (id,payload,status,"updatedAt")
VALUES ('00000000-0000-4000-8000-000000006104','{"action":"LEGACY_ALREADY_SENT","entityType":"Certification"}','SENT',transaction_timestamp());
