#!/bin/sh
# BadTower Station container entrypoint: wrangler dev --local in workerd,
# HTTPS on a mounted private CA, persistent state on the data volume.
set -eu
mkdir -p /tmp/.wrangler /tmp/home/.config/.wrangler /app/node_modules/.mf
exec npx wrangler dev --local \
  --ip 0.0.0.0 \
  --port 8787 \
  --local-protocol https \
  --https-key-path /run/badtower/server.key \
  --https-cert-path /run/badtower/server.crt \
  --persist-to /app/data/state \
  --env-file /run/badtower/.dev.vars \
  -c apps/station/wrangler.jsonc
