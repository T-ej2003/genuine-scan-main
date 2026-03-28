# syntax=docker/dockerfile:1.7

FROM node:20-bookworm-slim AS deps

WORKDIR /workspace/backend
RUN apt-get update \
  && apt-get install -y --no-install-recommends openssl ca-certificates \
  && rm -rf /var/lib/apt/lists/*

COPY backend/package*.json ./
RUN --mount=type=cache,target=/root/.npm npm ci \
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
RUN apt-get update \
  && apt-get install -y --no-install-recommends openssl ca-certificates \
  && rm -rf /var/lib/apt/lists/*

COPY backend/package*.json ./
COPY backend/prisma ./prisma
COPY backend/scripts ./scripts
COPY backend/local-print-agent ./local-print-agent
COPY --from=builder /workspace/backend/node_modules ./node_modules
COPY --from=builder /workspace/backend/dist ./dist
RUN chown -R node:node /app

EXPOSE 4000

USER node

CMD ["sh", "-c", "npx prisma migrate deploy && npm run start"]
