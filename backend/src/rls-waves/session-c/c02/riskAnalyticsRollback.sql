REVOKE ALL ON FUNCTION app_rls.risk_analytics_snapshot(text,text,text,text,text,integer,integer,timestamp without time zone) FROM PUBLIC;
DROP FUNCTION IF EXISTS app_rls.risk_analytics_snapshot(text,text,text,text,text,integer,integer,timestamp without time zone);
REVOKE ALL ON FUNCTION app_rls.risk_analytics_session_valid() FROM PUBLIC;
DROP FUNCTION IF EXISTS app_rls.risk_analytics_session_valid();
