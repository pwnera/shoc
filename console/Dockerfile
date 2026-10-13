# Build the console, then serve it from nginx with the API proxied alongside.
# Base images are pinned by digest; Renovate moves the pins (docker:pinDigests).
FROM node:22-alpine@sha256:0a7108bf6c7bf5de370ffb1a3ed6be93d405b43ff159f681a8d18c0e2bc2e402 AS build
WORKDIR /src
# npm ci alone: a lockfile out of step with package.json fails the build
# instead of resolving versions nobody reviewed.
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY . .
RUN npm run build

# Every nginx process runs as uid 101 and listens on 8080, as nginx.conf does.
FROM nginxinc/nginx-unprivileged:1.27-alpine@sha256:65e3e85dbaed8ba248841d9d58a899b6197106c23cb0ff1a132b7bfe0547e4c0
LABEL org.opencontainers.image.title="shoc-console" \
      org.opencontainers.image.description="An optional console for shoc" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="https://github.com/pwnera/shoc"
COPY deploy/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /src/dist /usr/share/nginx/html
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s CMD wget -qO- http://127.0.0.1:8080/ >/dev/null || exit 1
