DROP FUNCTION IF EXISTS app_rls.c03_reject_sensitive_action_approval(text,text);
DROP FUNCTION IF EXISTS app_rls.c03_approve_sensitive_action_approval(text,text);
DROP FUNCTION IF EXISTS app_rls.c03_review_sensitive_action_approval(text,text,text);
DROP FUNCTION IF EXISTS app_rls.c03_list_sensitive_action_approvals(text,integer,integer);
DROP FUNCTION IF EXISTS app_rls.c03_create_sensitive_action_approval(jsonb);
DROP FUNCTION IF EXISTS app_rls.c03_require_approval_actor(text);
