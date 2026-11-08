#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
  printf '%s\n' 'usage: scripts/deploy-cloudflare.sh <private-material-directory>' >&2
  exit 2
fi

node scripts/validate-deployment.mjs --target-dir "$1"
npx wrangler deploy --strict --minify --config wrangler.data.jsonc --secrets-file "$1/cloudflare-data-secrets.json"
npx wrangler deploy --strict --minify --config wrangler.operator.jsonc --secrets-file "$1/cloudflare-operator-secrets.json"
printf '%s\n' 'deployment complete'
