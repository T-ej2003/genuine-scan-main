DROP FUNCTION IF EXISTS app_auth.issue_authenticated_session_capability(text,text,text,text,timestamp without time zone);
DROP FUNCTION IF EXISTS app_auth.revoke_all_authenticated_session_capabilities(text,text,text);
DROP FUNCTION IF EXISTS app_auth.revoke_authenticated_session_capability(text,text,text,text);
DROP FUNCTION IF EXISTS app_auth.require_authenticated_session(text,text,text);
DROP FUNCTION IF EXISTS app_auth.auth_session_prepare(text,text,text);
