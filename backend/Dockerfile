FROM node:20-bookworm-slim AS deps

WORKDIR /workspace/backend
RUN apt-get update \
  && apt-get install -y --no-install-recommends openssl ca-certificates \
  && rm -rf /var/lib/apt/lists/*

COPY backend/package*.json ./
RUN npm ci

FROM deps AS builder

COPY backend/prisma ./prisma
RUN npx prisma generate

COPY backend/tsconfig.json ./tsconfig.json
COPY backend/src ./src
COPY backend/local-print-agent ./local-print-agent
COPY shared ../shared
RUN npm run build

FROM node:20-bookworm-slim AS runtime

WORKDIR /app
ENV NODE_ENV=production
ENV PORT=4000
RUN apt-get update \
  && apt-get install -y --no-install-recommends openssl ca-certificates \
  && rm -rf /var/lib/apt/lists/*

COPY backend/package*.json ./
COPY backend/prisma ./prisma
COPY backend/local-print-agent ./local-print-agent
COPY --from=builder /workspace/backend/node_modules ./node_modules
COPY --from=builder /workspace/backend/dist ./dist
RUN npx prisma generate \
  && chown -R node:node /app

EXPOSE 4000

USER node

CMD ["sh", "-c", "npx prisma migrate deploy && npm run start"]
