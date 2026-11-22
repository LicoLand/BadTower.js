FROM node:26-bookworm-slim@sha256:5df79989ed685e09f0a98019db4cebfb22fb9df1a53c0161664a011f7ff6b0f1 AS build
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci --ignore-scripts
COPY . .

FROM node:26-bookworm-slim@sha256:5df79989ed685e09f0a98019db4cebfb22fb9df1a53c0161664a011f7ff6b0f1
WORKDIR /app
RUN groupadd -r station && useradd -r -g station station
COPY --from=build /app /app
RUN mkdir -p /app/data/state /tmp/.wrangler && chown -R station:station /app/data /tmp/.wrangler && ln -s /tmp/.wrangler /app/.wrangler
USER station
EXPOSE 8787
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD node scripts/container-healthcheck.mjs
ENTRYPOINT ["sh", "scripts/container-entrypoint.sh"]
