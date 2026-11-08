#!/bin/sh
set -eu

config_dir=$(mktemp -d)
export XDG_CONFIG_HOME="$config_dir"
private_dir=data/private
node scripts/validate-deployment.mjs --target-dir "$private_dir"

exec npx wrangler dev \
  --local \
  --ip 0.0.0.0 \
  --port 8787 \
  --persist-to data/state \
  --env-file "$private_dir/.dev.vars" \
  --var BADTOWER_RUNTIME_MODE:local \
  --show-interactive-dev-session false \
  --log-level warn
