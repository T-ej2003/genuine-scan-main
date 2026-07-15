# syntax=docker/dockerfile:1.7

FROM node:24-bookworm-slim AS deps

WORKDIR /workspace/backend
ENV NPM_CONFIG_UPDATE_NOTIFIER=false
RUN apt-get update \
  && apt-get install -y --no-install-recommends openssl ca-certificates \
  && rm -rf /var/lib/apt/lists/*

COPY backend/package*.json ./
RUN --mount=type=cache,target=/root/.npm npm ci --prefer-offline --no-audit --no-fund \
  && ln -s /workspace/backend/node_modules /workspace/node_modules

FROM deps AS builder

ARG RUN_VERIFY=false
ARG GIT_SHA=unknown
ARG RELEASE_GIT_SHA=${GIT_SHA}
COPY backend/prisma ./prisma
COPY backend/prisma.config.ts ./prisma.config.ts
RUN npx prisma generate

COPY backend/tsconfig.json ./tsconfig.json
COPY backend/src ./src
COPY backend/tests ./tests
COPY backend/scripts ./scripts
# Connector release binaries are large and historical installers are not needed in
# the backend image. Build a latest-only runtime payload so production cannot
# accidentally serve old connector releases as the launch-required connector.
COPY backend/local-print-agent/releases ./local-print-agent/releases
RUN node scripts/create-connector-runtime-assets.mjs ./local-print-agent/releases ./local-print-agent-runtime
COPY shared ../shared
RUN if [ "$RUN_VERIFY" = "true" ]; then npm test; else npm run build; fi \
  && npm prune --omit=dev --no-audit --no-fund

FROM node:24-bookworm-slim AS runtime

WORKDIR /app
ARG GIT_SHA=unknown
ARG RELEASE_GIT_SHA=${GIT_SHA}
ENV NODE_ENV=production
ENV PORT=4000
ENV GIT_SHA=${GIT_SHA}
ENV RELEASE_GIT_SHA=${RELEASE_GIT_SHA}
ENV RUN_DB_MIGRATIONS_ON_START=false
LABEL org.opencontainers.image.revision=${RELEASE_GIT_SHA}
RUN apt-get update \
  && apt-get install -y --no-install-recommends openssl ca-certificates postgresql-client \
  && rm -rf /var/lib/apt/lists/*

COPY --chown=node:node backend/package*.json ./
COPY --chown=node:node backend/prisma ./prisma
COPY --chown=node:node backend/prisma.config.ts ./prisma.config.ts
COPY --chown=node:node backend/scripts ./scripts
COPY --chown=node:node documents/security/mscqr_staging_rls_shared_batch_phase_apply_2026-07-15.sql ./documents/security/
COPY --chown=node:node documents/security/mscqr_staging_rls_shared_batch_phase_rollback_2026-07-15.sql ./documents/security/
COPY --chown=node:node documents/security/mscqr_staging_rls_shared_batch_phase_verify_2026-07-15.sql ./documents/security/
# Runtime only needs the connector release manifest plus latest-release assets.
# Historical installers stay out of /app to reduce image size and avoid stale
# connector downloads while WebSocket production printing requires 2026.6.25+.
COPY --from=builder --chown=node:node /workspace/backend/local-print-agent-runtime ./local-print-agent
COPY --chown=node:node backend/docker/start-runtime.sh /usr/local/bin/start-runtime.sh
COPY --from=builder --chown=node:node /workspace/backend/node_modules ./node_modules
COPY --from=builder --chown=node:node /workspace/backend/dist ./dist
RUN chmod +x /usr/local/bin/start-runtime.sh

EXPOSE 4000

USER node

CMD ["/usr/local/bin/start-runtime.sh"]
