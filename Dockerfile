FROM node:20-bookworm-slim AS builder

WORKDIR /app

COPY package*.json ./
RUN npm ci

COPY . .

ARG VITE_API_URL=/api
ARG GIT_SHA=unknown
ARG VITE_APP_ENV=production
ARG VITE_SENTRY_DSN=
ENV VITE_API_URL=${VITE_API_URL}
ENV GIT_SHA=${GIT_SHA}
ENV VITE_APP_ENV=${VITE_APP_ENV}
ENV VITE_SENTRY_DSN=${VITE_SENTRY_DSN}

RUN npm run build

FROM nginx:1.27-alpine

COPY nginx.conf /etc/nginx/templates/default.http.conf
COPY nginx.https.conf /etc/nginx/templates/default.https.conf
COPY docker/nginx-entrypoint.sh /usr/local/bin/nginx-entrypoint.sh
COPY --from=builder /app/dist /usr/share/nginx/html

RUN chmod +x /usr/local/bin/nginx-entrypoint.sh

EXPOSE 80 443

CMD ["/usr/local/bin/nginx-entrypoint.sh"]
