#!/usr/bin/env bash

# Call before any AWS CLI command. The source is deliberately explicit: this
# shell boundary must not guess between a local profile and workflow OIDC.
configure_production_aws_credential_source() {
  case "${MSCQR_AWS_CREDENTIAL_SOURCE:-}" in
    github-oidc-release-deployer)
      : "${AWS_ACCESS_KEY_ID:?GitHub OIDC AWS_ACCESS_KEY_ID is required}"
      : "${AWS_SECRET_ACCESS_KEY:?GitHub OIDC AWS_SECRET_ACCESS_KEY is required}"
      : "${AWS_SESSION_TOKEN:?GitHub OIDC AWS_SESSION_TOKEN is required}"
      unset AWS_PROFILE AWS_DEFAULT_PROFILE AWS_CONFIG_FILE AWS_SHARED_CREDENTIALS_FILE AWS_SDK_LOAD_CONFIG AWS_SECURITY_TOKEN
      ;;
    github-access-keys)
      : "${AWS_ACCESS_KEY_ID:?GitHub access-key AWS_ACCESS_KEY_ID is required}"
      : "${AWS_SECRET_ACCESS_KEY:?GitHub access-key AWS_SECRET_ACCESS_KEY is required}"
      unset AWS_PROFILE AWS_DEFAULT_PROFILE AWS_CONFIG_FILE AWS_SHARED_CREDENTIALS_FILE AWS_SDK_LOAD_CONFIG AWS_SECURITY_TOKEN
      ;;
    named-profile)
      : "${MSCQR_AWS_NAMED_PROFILE:?MSCQR_AWS_NAMED_PROFILE is required for named-profile execution}"
      unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_SECURITY_TOKEN AWS_DEFAULT_PROFILE AWS_SDK_LOAD_CONFIG
      export AWS_PROFILE="$MSCQR_AWS_NAMED_PROFILE"
      ;;
    *)
      echo "MSCQR_AWS_CREDENTIAL_SOURCE must explicitly select github-oidc-release-deployer, github-access-keys, or named-profile." >&2
      return 1
      ;;
  esac
  export AWS_EC2_METADATA_DISABLED=true
}
