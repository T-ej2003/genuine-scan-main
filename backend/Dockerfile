# syntax=docker/dockerfile:1.7

FROM node:20-bookworm-slim AS deps

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
COPY backend/prisma ./prisma
RUN npx prisma generate

COPY backend/tsconfig.json ./tsconfig.json
COPY backend/src ./src
COPY backend/tests ./tests
COPY backend/scripts ./scripts
COPY backend/local-print-agent ./local-print-agent
COPY shared ../shared
RUN if [ "$RUN_VERIFY" = "true" ]; then npm test; else npm run build; fi

FROM node:20-bookworm-slim AS runtime

WORKDIR /app
ARG GIT_SHA=unknown
ENV NODE_ENV=production
ENV PORT=4000
ENV GIT_SHA=${GIT_SHA}
ENV RUN_DB_MIGRATIONS_ON_START=false
RUN apt-get update \
  && apt-get install -y --no-install-recommends openssl ca-certificates \
  && rm -rf /var/lib/apt/lists/*

COPY --chown=node:node backend/package*.json ./
COPY --chown=node:node backend/prisma ./prisma
COPY --chown=node:node backend/scripts ./scripts
COPY --chown=node:node backend/local-print-agent ./local-print-agent
COPY --chown=node:node backend/docker/start-runtime.sh /usr/local/bin/start-runtime.sh
COPY --from=builder --chown=node:node /workspace/backend/node_modules ./node_modules
COPY --from=builder --chown=node:node /workspace/backend/dist ./dist
RUN chmod +x /usr/local/bin/start-runtime.sh

EXPOSE 4000

USER node

CMD ["/usr/local/bin/start-runtime.sh"]
