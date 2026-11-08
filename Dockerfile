FROM node:24-bookworm-slim@sha256:3638d9a6fe4030bd716be989438248074489337ba3275657f93595428be4fc03

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts && npm rebuild esbuild workerd

COPY . .
RUN chmod 755 scripts/container-entrypoint.sh \
  && mkdir -p data/private data/state \
  && chmod 700 data/private data/state \
  && chown -R node:node data

USER node
EXPOSE 8787
VOLUME ["/app/data"]
HEALTHCHECK --interval=15s --timeout=3s --start-period=20s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:8787/healthz').then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))"
ENTRYPOINT ["scripts/container-entrypoint.sh"]
