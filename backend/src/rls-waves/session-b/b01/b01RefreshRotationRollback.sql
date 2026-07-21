-- Clean-room rollback is destructive only to the green package database.
DROP FUNCTION IF EXISTS app_auth.complete_refresh_token_rotation(text,text[],text,text,text,timestamp without time zone,text,text,timestamp without time zone,timestamp without time zone,timestamp without time zone,text);
DROP FUNCTION IF EXISTS app_auth.revoke_refresh_token_scope(text,text[],text,text,text,timestamp without time zone,text);
DROP FUNCTION IF EXISTS app_auth.create_refresh_mfa_challenge(text,text[],text,text,text,integer,text,text[],text,text,integer,timestamp without time zone,timestamp without time zone,text);
DROP FUNCTION IF EXISTS app_auth.load_refresh_session_state(text,text[],text,text,timestamp without time zone,text);
DROP FUNCTION IF EXISTS app_auth.claim_refresh_token_rotation(text[],timestamp without time zone,text);
DROP FUNCTION IF EXISTS app_auth.b01_audit(text,text,timestamp without time zone);
DROP FUNCTION IF EXISTS app_auth.b01_bind_bearer(text[],text);
