# syntax=docker/dockerfile:1.7
FROM node:24-bookworm-slim AS build
WORKDIR /app/backend
ENV NPM_CONFIG_UPDATE_NOTIFIER=false
COPY backend/package*.json ./
RUN --mount=type=cache,target=/root/.npm npm ci --no-audit --no-fund
COPY backend/prisma ./prisma
COPY backend/prisma.config.ts ./prisma.config.ts
RUN npx prisma generate && npm prune --omit=dev --no-audit --no-fund

FROM node:24-bookworm-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
  && rm -rf /var/lib/apt/lists/*
ARG GIT_SHA
ENV NODE_ENV=production GIT_SHA=${GIT_SHA}
LABEL org.opencontainers.image.revision=${GIT_SHA} org.opencontainers.image.title=mscqr-victoria-recovery
COPY --from=build --chown=node:node /app/backend/node_modules /app/backend/node_modules
COPY --from=build --chown=node:node /app/backend/package.json /app/backend/package.json
COPY --chown=node:node backend/scripts/victoria-failed-onboarding-recovery.mjs /app/backend/scripts/victoria-failed-onboarding-recovery.mjs
COPY --chown=node:node backend/scripts/victoria-rds-iam-token.mjs /app/backend/scripts/victoria-rds-iam-token.mjs
COPY --chown=node:node scripts/aws/victoria-recovery-authorization.mjs /app/scripts/aws/victoria-recovery-authorization.mjs
COPY --chown=node:node scripts/aws/victoria-recovery-result.mjs /app/scripts/aws/victoria-recovery-result.mjs
COPY --chown=node:node scripts/aws/publish-victoria-recovery-authorization.mjs /app/scripts/aws/publish-victoria-recovery-authorization.mjs
COPY --chown=node:node scripts/aws/register-victoria-recovery-task-definition.mjs /app/scripts/aws/register-victoria-recovery-task-definition.mjs
COPY --chown=node:node scripts/aws/production-github-environment-approval.mjs /app/scripts/aws/production-github-environment-approval.mjs
COPY --chown=node:node scripts/security/victoria-recovery-dependencies.json /app/scripts/security/victoria-recovery-dependencies.json
COPY --chown=node:node scripts/security/victoria-recovery-sql.mjs /app/scripts/security/victoria-recovery-sql.mjs
COPY --chown=node:node scripts/security/victoria-recovery-installation.mjs /app/scripts/security/victoria-recovery-installation.mjs
COPY --chown=node:node backend/src/rls-waves/session-c/c05/victoriaRecovery.template.sql /app/backend/src/rls-waves/session-c/c05/victoriaRecovery.template.sql
COPY --chown=node:node backend/src/rls-waves/session-c/c05/victoriaRecovery.sql /app/backend/src/rls-waves/session-c/c05/victoriaRecovery.sql
COPY --chown=node:node .github/workflows/execute-victoria-onboarding-recovery.yml /app/.github/workflows/execute-victoria-onboarding-recovery.yml
COPY --chown=node:node infra/aws/terraform/production-victoria-recovery/task-definition.json /app/infra/aws/terraform/production-victoria-recovery/task-definition.json
COPY --chown=node:node infra/aws/terraform/production-victoria-recovery/Dockerfile /app/infra/aws/terraform/production-victoria-recovery/Dockerfile
COPY --chown=node:node infra/aws/terraform/production-victoria-recovery/main.tf /app/infra/aws/terraform/production-victoria-recovery/main.tf
COPY --chown=node:node infra/aws/terraform/production-victoria-recovery/variables.tf /app/infra/aws/terraform/production-victoria-recovery/variables.tf
COPY --chown=node:node infra/aws/terraform/production-victoria-recovery/outputs.tf /app/infra/aws/terraform/production-victoria-recovery/outputs.tf
COPY --chown=node:node infra/aws/terraform/production-victoria-recovery/versions.tf /app/infra/aws/terraform/production-victoria-recovery/versions.tf
COPY --chown=node:node infra/aws/terraform/lambda/victoria-recovery-broker/index.mjs /app/infra/aws/terraform/lambda/victoria-recovery-broker/index.mjs
COPY --chown=node:node infra/aws/terraform/lambda/victoria-recovery-broker/task-cleanup.mjs /app/infra/aws/terraform/lambda/victoria-recovery-broker/task-cleanup.mjs
USER node
ENTRYPOINT ["node", "/app/backend/scripts/victoria-failed-onboarding-recovery.mjs"]
CMD []
