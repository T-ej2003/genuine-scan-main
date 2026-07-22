DROP FUNCTION IF EXISTS app_rls.scheduled_fail_compliance_pack_job(text,text,text,text,text);
DROP FUNCTION IF EXISTS app_rls.scheduled_complete_compliance_pack_job(text,text,text,text,jsonb);
DROP FUNCTION IF EXISTS app_rls.scheduled_get_compliance_pack_job(text,text,text,text);
DROP FUNCTION IF EXISTS app_rls.claim_compliance_pack_slice(text,text,timestamp without time zone,integer);
DROP FUNCTION IF EXISTS app_rls.scheduled_job_queue_audit(text,text,text,jsonb);
DROP FUNCTION IF EXISTS app_rls.revoke_scheduled_job_credential(text,text,text);
DROP FUNCTION IF EXISTS app_rls.provision_scheduled_job_credential(text,text,text,timestamp with time zone,text,text);
DROP FUNCTION IF EXISTS app_rls.scheduled_job_prepare(text,text,text,text);
