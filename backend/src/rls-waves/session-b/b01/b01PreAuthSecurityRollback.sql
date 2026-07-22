DROP FUNCTION IF EXISTS app_auth.consume_email_verification_token(text[],timestamp without time zone);
DROP FUNCTION IF EXISTS app_auth.consume_invitation_token(text[],text,text,timestamp without time zone,text,text,text);
DROP FUNCTION IF EXISTS app_auth.lookup_invitation_token(text[],timestamp without time zone);
DROP FUNCTION IF EXISTS app_auth.consume_password_reset_token(text[],text,timestamp without time zone);
DROP FUNCTION IF EXISTS app_auth.request_password_reset(text,text,timestamp without time zone,timestamp without time zone,text,text);
DROP FUNCTION IF EXISTS app_auth.record_password_failure(text,timestamp without time zone,integer,integer);
DROP FUNCTION IF EXISTS app_auth.lookup_password_user(text);
DROP FUNCTION IF EXISTS app_auth.b01_preauth_audit(text,text,text,timestamp without time zone,jsonb);
