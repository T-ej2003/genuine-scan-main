#!/usr/bin/env bash

# Call before any AWS CLI command. The source is deliberately explicit: this
# shell boundary must not guess between a local profile and workflow OIDC.
clear_production_aws_credential_overrides() {
  unset AWS_PROFILE AWS_DEFAULT_PROFILE AWS_CONFIG_FILE AWS_SHARED_CREDENTIALS_FILE AWS_SDK_LOAD_CONFIG
  unset AWS_ROLE_ARN AWS_WEB_IDENTITY_TOKEN_FILE AWS_ROLE_SESSION_NAME
  unset AWS_CONTAINER_CREDENTIALS_FULL_URI AWS_CONTAINER_CREDENTIALS_RELATIVE_URI AWS_CONTAINER_AUTHORIZATION_TOKEN AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE
  unset AWS_ENDPOINT_URL AWS_CA_BUNDLE AWS_USE_FIPS_ENDPOINT AWS_USE_DUALSTACK_ENDPOINT
  unset AWS_METADATA_SERVICE_TIMEOUT AWS_METADATA_SERVICE_NUM_ATTEMPTS AWS_EC2_METADATA_SERVICE_ENDPOINT AWS_EC2_METADATA_SERVICE_ENDPOINT_MODE
  local name
  while IFS= read -r name; do unset "$name"; done < <(compgen -A variable AWS_ENDPOINT_URL_)
}

configure_production_aws_credential_source() {
  case "${MSCQR_AWS_CREDENTIAL_SOURCE:-}" in
    github-oidc-release-deployer)
      : "${AWS_ACCESS_KEY_ID:?GitHub OIDC AWS_ACCESS_KEY_ID is required}"
      : "${AWS_SECRET_ACCESS_KEY:?GitHub OIDC AWS_SECRET_ACCESS_KEY is required}"
      : "${AWS_SESSION_TOKEN:?GitHub OIDC AWS_SESSION_TOKEN is required}"
      clear_production_aws_credential_overrides
      unset AWS_SECURITY_TOKEN
      ;;
    github-access-keys)
      : "${AWS_ACCESS_KEY_ID:?GitHub access-key AWS_ACCESS_KEY_ID is required}"
      : "${AWS_SECRET_ACCESS_KEY:?GitHub access-key AWS_SECRET_ACCESS_KEY is required}"
      clear_production_aws_credential_overrides
      unset AWS_SECURITY_TOKEN
      ;;
    named-profile)
      : "${MSCQR_AWS_NAMED_PROFILE:?MSCQR_AWS_NAMED_PROFILE is required for named-profile execution}"
      clear_production_aws_credential_overrides
      unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_SECURITY_TOKEN
      export AWS_PROFILE="$MSCQR_AWS_NAMED_PROFILE"
      ;;
    *)
      echo "MSCQR_AWS_CREDENTIAL_SOURCE must explicitly select github-oidc-release-deployer, github-access-keys, or named-profile." >&2
      return 1
      ;;
  esac
  export AWS_EC2_METADATA_DISABLED=true
}
