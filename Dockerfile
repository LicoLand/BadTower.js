FROM node:24-bookworm-slim@sha256:3638d9a6fe4030bd716be989438248074489337ba3275657f93595428be4fc03 AS build
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci --ignore-scripts
COPY . .

FROM node:24-bookworm-slim@sha256:3638d9a6fe4030bd716be989438248074489337ba3275657f93595428be4fc03
WORKDIR /app
RUN groupadd -r station && useradd -r -g station station
COPY --from=build /app /app
RUN mkdir -p /app/data/state /tmp/.wrangler && chown -R station:station /app/data /tmp/.wrangler && ln -s /tmp/.wrangler /app/.wrangler
USER station
EXPOSE 8787
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD node scripts/container-healthcheck.mjs
ENTRYPOINT ["sh", "scripts/container-entrypoint.sh"]
