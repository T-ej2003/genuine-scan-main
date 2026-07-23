DROP FUNCTION IF EXISTS app_rls.create_refresh_token(text,text,text,timestamp without time zone,text,text,timestamp without time zone,timestamp without time zone,timestamp without time zone);
DROP FUNCTION IF EXISTS app_rls.record_auth_session_risk_signal(integer,text,text[],text,text,timestamp without time zone,text,text,text,timestamp without time zone,integer,text);
DROP FUNCTION IF EXISTS app_rls.load_recent_auth_session_risk_inputs(integer);
DROP FUNCTION IF EXISTS app_rls.require_recent_mfa_session(text,timestamp without time zone,integer);
DROP FUNCTION IF EXISTS app_rls.revoke_refresh_token_by_id(text,text,text,timestamp without time zone);
DROP FUNCTION IF EXISTS app_rls.find_refresh_token_by_id(text,text);
DROP FUNCTION IF EXISTS app_rls.load_authenticated_actor();
DROP FUNCTION IF EXISTS app_rls.revalidate_authenticated_actor(text,text,text,text,timestamp without time zone,text);
DROP FUNCTION IF EXISTS app_rls.b01_authenticated_actor(text,text,text);
