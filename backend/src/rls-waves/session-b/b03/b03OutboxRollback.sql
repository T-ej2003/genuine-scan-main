DROP FUNCTION IF EXISTS app_rls.fail_security_event_outbox(text,text,timestamp without time zone,integer,text);
DROP FUNCTION IF EXISTS app_rls.complete_security_event_outbox(text,text,timestamp without time zone,text);
DROP FUNCTION IF EXISTS app_rls.claim_security_event_outbox_slice(timestamp without time zone,integer,text);
DROP FUNCTION IF EXISTS app_rls.enqueue_security_event_outbox(text,jsonb,text,text,text,text,text,text,text,timestamp without time zone);
DROP FUNCTION IF EXISTS app_rls.fail_audit_log_outbox(text,text,timestamp without time zone,integer,text);
DROP FUNCTION IF EXISTS app_rls.consume_audit_log_outbox(text,text,timestamp without time zone);
DROP FUNCTION IF EXISTS app_rls.claim_audit_log_outbox_slice(timestamp without time zone,integer);
DROP FUNCTION IF EXISTS app_rls.enqueue_audit_log_outbox(jsonb,text,text,text,text,text,text,text,text,timestamp without time zone,text);
DROP FUNCTION IF EXISTS app_rls.b03_bind_outbox_operation(text,text,text);
