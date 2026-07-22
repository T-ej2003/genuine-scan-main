# Named SQL function recovery

Generated from tracked source and all local Git refs. Fixture SQL is evidence only and is never deployable production SQL.

- fixture-only definition: 13
- no definition found: 48
- production definition recovered: 46
- repository contract only: 9

| Function | Classification | Definition | Commit | Deployable |
|---|---|---|---|---|
| `app_auth.claim_refresh_token_rotation` | production definition recovered | backend/src/rls-waves/session-b/b01/b01RefreshRotationFunctions.sql | 4add7dec147d | yes |
| `app_auth.complete_refresh_token_rotation` | production definition recovered | backend/src/rls-waves/session-b/b01/b01RefreshRotationFunctions.sql | 4add7dec147d | yes |
| `app_auth.consume_email_verification_token` | production definition recovered | backend/src/rls-waves/session-b/b01/b01PreAuthSecurityFunctions.sql | a2a9efe68724 | yes |
| `app_auth.consume_invitation_token` | production definition recovered | backend/src/rls-waves/session-b/b01/b01PreAuthSecurityFunctions.sql | a2a9efe68724 | yes |
| `app_auth.consume_password_reset_token` | production definition recovered | backend/src/rls-waves/session-b/b01/b01PreAuthSecurityFunctions.sql | a2a9efe68724 | yes |
| `app_auth.create_refresh_mfa_challenge` | production definition recovered | backend/src/rls-waves/session-b/b01/b01RefreshRotationFunctions.sql | 4add7dec147d | yes |
| `app_auth.issue_authenticated_session_capability` | production definition recovered | backend/src/rls-waves/session-b/b01/authenticatedSessionCapabilityFunctions.sql | 4add7dec147d | yes |
| `app_auth.load_refresh_session_state` | production definition recovered | backend/src/rls-waves/session-b/b01/b01RefreshRotationFunctions.sql | 4add7dec147d | yes |
| `app_auth.lookup_invitation_token` | production definition recovered | backend/src/rls-waves/session-b/b01/b01PreAuthSecurityFunctions.sql | a2a9efe68724 | yes |
| `app_auth.lookup_password_user` | production definition recovered | backend/src/rls-waves/session-b/b01/b01PreAuthSecurityFunctions.sql | a2a9efe68724 | yes |
| `app_auth.record_password_failure` | production definition recovered | backend/src/rls-waves/session-b/b01/b01PreAuthSecurityFunctions.sql | a2a9efe68724 | yes |
| `app_auth.request_password_reset` | production definition recovered | backend/src/rls-waves/session-b/b01/b01PreAuthSecurityFunctions.sql | a2a9efe68724 | yes |
| `app_auth.require_authenticated_session` | production definition recovered | backend/src/rls-waves/session-b/b01/authenticatedSessionCapabilityFunctions.sql | 6a6ca469499b | yes |
| `app_auth.revoke_all_authenticated_session_capabilities` | production definition recovered | backend/src/rls-waves/session-b/b01/authenticatedSessionCapabilityFunctions.sql | 6a6ca469499b | yes |
| `app_auth.revoke_authenticated_session_capability` | production definition recovered | backend/src/rls-waves/session-b/b01/authenticatedSessionCapabilityFunctions.sql | 6a6ca469499b | yes |
| `app_auth.revoke_refresh_token_scope` | production definition recovered | backend/src/rls-waves/session-b/b01/b01RefreshRotationFunctions.sql | 4add7dec147d | yes |
| `app_rls.b03_claim_incident_email_delivery` | no definition found | none | none | no |
| `app_rls.b03_complete_incident_email_delivery` | no definition found | none | none | no |
| `app_rls.b03_create_role_notifications` | no definition found | none | none | no |
| `app_rls.b03_create_user_notification` | no definition found | none | none | no |
| `app_rls.b03_list_notifications_for_user` | no definition found | none | none | no |
| `app_rls.b03_mark_all_notifications_read` | no definition found | none | none | no |
| `app_rls.b03_mark_notification_emailed` | no definition found | none | none | no |
| `app_rls.b03_mark_notification_read` | no definition found | none | none | no |
| `app_rls.b03_primary_superadmin_email` | no definition found | none | none | no |
| `app_rls.b03_resolve_incident_email_actor` | no definition found | none | none | no |
| `app_rls.b03_resolve_incident_notification_scope` | no definition found | none | none | no |
| `app_rls.b03_superadmin_alert_emails` | no definition found | none | none | no |
| `app_rls.batch_inventory_rollups` | repository contract only | none | 4add7dec147d | no |
| `app_rls.batch_operational_rows` | repository contract only | none | 4add7dec147d | no |
| `app_rls.batch_operational_scope` | repository contract only | none | 4add7dec147d | no |
| `app_rls.batch_operational_total` | repository contract only | none | 4add7dec147d | no |
| `app_rls.batch_reservable_qr_summaries` | repository contract only | none | 4add7dec147d | no |
| `app_rls.batch_status_fallback` | repository contract only | none | 4add7dec147d | no |
| `app_rls.batch_unassigned_ranges` | repository contract only | none | 4add7dec147d | no |
| `app_rls.c02_fraud_report_network_details` | production definition recovered | backend/src/rls-waves/session-c/c02/auditTrace.sql | cc14d113f577 | yes |
| `app_rls.c02_respond_fraud_report` | production definition recovered | backend/src/rls-waves/session-c/c02/auditTrace.sql | cc14d113f577 | yes |
| `app_rls.c03_add_incident_evidence` | no definition found | none | none | no |
| `app_rls.c03_approve_sensitive_action_approval` | no definition found | none | none | no |
| `app_rls.c03_assert_restricted_identity` | no definition found | none | none | no |
| `app_rls.c03_build_incident_evidence_audit_snapshot` | no definition found | none | none | no |
| `app_rls.c03_complete_compliance_pack_job` | production definition recovered | backend/src/rls-waves/session-c/c03/c03AuthenticatedBoundaries.sql | 6a6ca469499b | yes |
| `app_rls.c03_complete_compliance_pack_rebuild` | production definition recovered | backend/src/rls-waves/session-c/c03/c03AuthenticatedBoundaries.sql | 6a6ca469499b | yes |
| `app_rls.c03_compute_incident_severity` | no definition found | none | none | no |
| `app_rls.c03_compute_incident_spam_signal` | no definition found | none | none | no |
| `app_rls.c03_create_ir_incident` | no definition found | none | none | no |
| `app_rls.c03_create_policy_rule` | production definition recovered | backend/src/rls-waves/session-c/c03/c03Policy.sql | d4edf6e4a63e | yes |
| `app_rls.c03_create_public_incident_report` | no definition found | none | none | no |
| `app_rls.c03_create_sensitive_action_approval` | no definition found | none | none | no |
| `app_rls.c03_fail_compliance_pack_job` | production definition recovered | backend/src/rls-waves/session-c/c03/c03AuthenticatedBoundaries.sql | 6a6ca469499b | yes |
| `app_rls.c03_generate_compliance_report` | production definition recovered | backend/src/rls-waves/session-c/c03/c03GovernanceFunctions.sql | fb555a0315ba | yes |
| `app_rls.c03_get_compliance_pack_job` | production definition recovered | backend/src/rls-waves/session-c/c03/c03AuthenticatedBoundaries.sql | 6a6ca469499b | yes |
| `app_rls.c03_get_incident_detail` | no definition found | none | none | no |
| `app_rls.c03_get_incident_evidence_file_by_storage_key` | production definition recovered | backend/src/rls-waves/session-c/c03/c03AuthenticatedBoundaries.sql | 6a6ca469499b | yes |
| `app_rls.c03_get_ir_incident_detail` | no definition found | none | none | no |
| `app_rls.c03_get_or_create_retention_policy` | production definition recovered | backend/src/rls-waves/session-c/c03/c03GovernanceFunctions.sql | fb555a0315ba | yes |
| `app_rls.c03_link_ir_alert_incident` | no definition found | none | none | no |
| `app_rls.c03_list_incidents` | no definition found | none | none | no |
| `app_rls.c03_list_ir_alerts` | no definition found | none | none | no |
| `app_rls.c03_list_platform_policy_rules` | production definition recovered | backend/src/rls-waves/session-c/c03/c03Policy.sql | d4edf6e4a63e | yes |
| `app_rls.c03_list_policy_rules` | production definition recovered | backend/src/rls-waves/session-c/c03/c03Policy.sql | d4edf6e4a63e | yes |
| `app_rls.c03_list_sensitive_action_approvals` | no definition found | none | none | no |
| `app_rls.c03_patch_incident` | no definition found | none | none | no |
| `app_rls.c03_prepare_incident_communication` | no definition found | none | none | no |
| `app_rls.c03_record_incident_communication_delivery` | no definition found | none | none | no |
| `app_rls.c03_record_incident_event` | no definition found | none | none | no |
| `app_rls.c03_reject_sensitive_action_approval` | no definition found | none | none | no |
| `app_rls.c03_revalidate_compliance_pack_job_actor_scope` | production definition recovered | backend/src/rls-waves/session-c/c03/c03AuthenticatedBoundaries.sql | 6a6ca469499b | yes |
| `app_rls.c03_review_incident_customer_trust` | no definition found | none | none | no |
| `app_rls.c03_run_retention_lifecycle` | production definition recovered | backend/src/rls-waves/session-c/c03/c03GovernanceFunctions.sql | fb555a0315ba | yes |
| `app_rls.c03_start_compliance_pack_job` | production definition recovered | backend/src/rls-waves/session-c/c03/c03AuthenticatedBoundaries.sql | 6a6ca469499b | yes |
| `app_rls.c03_update_policy_rule` | production definition recovered | backend/src/rls-waves/session-c/c03/c03Policy.sql | d4edf6e4a63e | yes |
| `app_rls.c03_update_retention_policy` | production definition recovered | backend/src/rls-waves/session-c/c03/c03GovernanceFunctions.sql | fb555a0315ba | yes |
| `app_rls.c03_upsert_tenant_feature_flag` | production definition recovered | backend/src/rls-waves/session-c/c03/c03GovernanceFunctions.sql | fb555a0315ba | yes |
| `app_rls.change_authenticated_password` | no definition found | none | none | no |
| `app_rls.claim_audit_log_outbox_slice` | no definition found | none | none | no |
| `app_rls.claim_compliance_pack_slice` | production definition recovered | backend/src/rls-waves/session-b/b03/scheduledJobIdentityFunctions.sql | none | yes |
| `app_rls.claim_security_event_outbox_slice` | no definition found | none | none | no |
| `app_rls.complete_security_event_outbox` | no definition found | none | none | no |
| `app_rls.consume_audit_log_outbox` | no definition found | none | none | no |
| `app_rls.create_refresh_token` | fixture-only definition | backend/tests/rls-wave-b/b01/refreshSessionPostgres18.fixture.sql | 62b73a98b6e0 | no |
| `app_rls.dashboard_snapshot_data` | repository contract only | none | 4add7dec147d | no |
| `app_rls.dashboard_snapshot_scope` | repository contract only | none | 4add7dec147d | no |
| `app_rls.enqueue_audit_log_outbox` | fixture-only definition | backend/tests/rls-wave-b/b01/refreshSessionPostgres18.fixture.sql | 62b73a98b6e0 | no |
| `app_rls.enqueue_security_event_outbox` | no definition found | none | none | no |
| `app_rls.fail_audit_log_outbox` | no definition found | none | none | no |
| `app_rls.fail_security_event_outbox` | no definition found | none | none | no |
| `app_rls.find_refresh_token_by_hashes` | fixture-only definition | backend/tests/rls-wave-b/b01/refreshSessionPostgres18.fixture.sql | 45961044fde6 | no |
| `app_rls.find_refresh_token_by_id` | fixture-only definition | backend/tests/rls-wave-b/b01/refreshSessionPostgres18.fixture.sql | 45961044fde6 | no |
| `app_rls.list_active_refresh_tokens` | fixture-only definition | backend/tests/rls-wave-b/b01/refreshSessionPostgres18.fixture.sql | 45961044fde6 | no |
| `app_rls.load_authenticated_actor` | fixture-only definition | backend/tests/rls-wave-b/b01/refreshSessionPostgres18.fixture.sql | 62b73a98b6e0 | no |
| `app_rls.load_authenticated_password_actor` | no definition found | none | none | no |
| `app_rls.load_recent_auth_session_risk_inputs` | no definition found | none | none | no |
| `app_rls.platform_audit_log_details` | production definition recovered | backend/src/rls-waves/session-c/c02/auditTrace.sql | 4add7dec147d | yes |
| `app_rls.prepare_invitation` | fixture-only definition | backend/tests/rls-wave-b/b01/invitationPostgres18.fixture.sql | 62b73a98b6e0 | no |
| `app_rls.prove_authenticated_password_step_up` | no definition found | none | none | no |
| `app_rls.record_auth_session_risk_signal` | no definition found | none | none | no |
| `app_rls.request_authenticated_email_change` | no definition found | none | none | no |
| `app_rls.require_recent_mfa_session` | fixture-only definition | backend/tests/rls-wave-b/b01/refreshSessionPostgres18.fixture.sql | 62b73a98b6e0 | no |
| `app_rls.require_recent_sensitive_session` | no definition found | none | none | no |
| `app_rls.revalidate_authenticated_actor` | fixture-only definition | backend/tests/rls-wave-b/b01/refreshSessionPostgres18.fixture.sql | 62b73a98b6e0 | no |
| `app_rls.revoke_all_refresh_tokens` | fixture-only definition | backend/tests/rls-wave-b/b01/refreshSessionPostgres18.fixture.sql | 45961044fde6 | no |
| `app_rls.revoke_password_only_refresh_tokens` | fixture-only definition | backend/tests/rls-wave-b/b01/refreshSessionPostgres18.fixture.sql | 45961044fde6 | no |
| `app_rls.revoke_refresh_token_by_hashes` | fixture-only definition | backend/tests/rls-wave-b/b01/refreshSessionPostgres18.fixture.sql | 45961044fde6 | no |
| `app_rls.revoke_refresh_token_by_id` | fixture-only definition | backend/tests/rls-wave-b/b01/refreshSessionPostgres18.fixture.sql | 62b73a98b6e0 | no |
| `app_rls.scheduled_complete_compliance_pack_job` | production definition recovered | backend/src/rls-waves/session-b/b03/scheduledJobIdentityFunctions.sql | none | yes |
| `app_rls.scheduled_fail_compliance_pack_job` | production definition recovered | backend/src/rls-waves/session-b/b03/scheduledJobIdentityFunctions.sql | none | yes |
| `app_rls.session_c_create_licensee` | production definition recovered | backend/src/rls-waves/session-c/c01/administration.sql | 3bcba7fb4749 | yes |
| `app_rls.session_c_create_user` | production definition recovered | backend/src/rls-waves/session-c/c01/administration.sql | 3bcba7fb4749 | yes |
| `app_rls.session_c_delete_licensee` | production definition recovered | backend/src/rls-waves/session-c/c01/administration.sql | 3bcba7fb4749 | yes |
| `app_rls.session_c_delete_user` | production definition recovered | backend/src/rls-waves/session-c/c01/administration.sql | 3bcba7fb4749 | yes |
| `app_rls.session_c_restore_manufacturer` | production definition recovered | backend/src/rls-waves/session-c/c01/administration.sql | 3bcba7fb4749 | yes |
| `app_rls.session_c_update_licensee` | production definition recovered | backend/src/rls-waves/session-c/c01/administration.sql | 3bcba7fb4749 | yes |
| `app_rls.session_c_update_user` | production definition recovered | backend/src/rls-waves/session-c/c01/administration.sql | 3bcba7fb4749 | yes |
| `app_rls.session_c_upsert_manufacturer_licensee_link` | production definition recovered | backend/src/rls-waves/session-c/c01/administration.sql | 3bcba7fb4749 | yes |
| `app_rls.update_authenticated_profile` | no definition found | none | none | no |
