REVOKE ALL ON FUNCTION app_rls.c02_audit_trace_session_valid() FROM PUBLIC;
DROP FUNCTION IF EXISTS app_rls.c02_respond_fraud_report(text,text,text,boolean);
DROP FUNCTION IF EXISTS app_rls.c02_fraud_report_network_details(text[]);
DROP FUNCTION IF EXISTS app_rls.platform_audit_log_details(text[]);
DROP FUNCTION IF EXISTS app_rls.c02_audit_trace_actor_valid(text);
DROP FUNCTION IF EXISTS app_rls.c02_audit_trace_session_valid();
