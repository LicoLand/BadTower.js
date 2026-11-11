# Operations

All privileged material lives in a private directory you pass with
`--dir`. Nothing private is tracked in this repository.

## Setup

```sh
npm run station -- init --dir ~/private/badtower
```

Creates `station.key` (32-byte base64url, 0600) and `.dev.vars` for
`wrangler dev` / the container. Refuses to overwrite.

## Invitations

```sh
npm run station -- invite --dir ~/private/badtower [--bind-within 7d] [--out FILE]
```

Mints a random mailbox id and a `btm1` credential bound to it;
`--bind-within` caps only the first binding (s/m/h/d/w suffixes). The
file is written 0600; stdout shows only the mailbox id hex and the path.

## Revocation

```sh
npm run station -- revoke --dir ~/private/badtower --station https://HOST --mailbox HEX [--ca PEM]
```

## TLS (self-hosted)

```sh
npm run station -- tls --dir ~/private/badtower --ip 10.0.0.5 [--dns name]
```

Private CA (ECDSA P-256, 10y) and server certificate (SAN ip/dns, 825d)
under `<dir>/tls/` via openssl; private keys 0600.

## Cloudflare deploy

```sh
npm run station -- cloudflare-deploy --dir ~/private/badtower [--domain NAME]
```

Deploys with `wrangler deploy --secrets-file .dev.vars` (uploads
`BADTOWER_STATION_KEY` from the file, never argv). `--domain` writes a
temporary `wrangler.deploy.jsonc` with `workers_dev` disabled, deploys it
with `--domains NAME`, then deletes it. Uses the operator's existing
wrangler login.

## Self-hosted deploy

```sh
npm run station -- docker-deploy --ssh HOST --dir ~/private/badtower --listen IP:PORT [--remote-dir PATH]
```

Builds `badtower-station:local` on the operator machine for the remote
daemon's architecture (`docker version --format {{.Server.Arch}}`, then
`docker build --platform linux/<arch>`), streams it with
`docker save | ssh HOST docker load` — no tar file on either side — then
copies only `compose.yml`, a generated `.env` carrying `LISTEN`, and the
secrets (`0600`, PowerShell/posix owner-only handling), and runs
`docker compose up -d --pull never --no-build`. The remote needs Docker
only: no source tree, no registry access. Re-deploys keep the
`badtower-state` volume; a later manual `docker compose up` keeps the
`--listen` binding because it lives in the remote `.env`.

## Health

```sh
npm run station -- health --station https://HOST [--ca PEM]
```

## Container

`Dockerfile` + `compose.yml` run `wrangler dev --local` (workerd) with
HTTPS from the mounted private CA, `--persist-to` on the `badtower-state`
volume, read-only root, dropped caps and no-new-privileges. The container
healthcheck verifies TLS against the mounted `ca.crt`. Mount
`./secrets/` with `.dev.vars`, `server.key`, `server.crt`, `ca.crt` (from
`init` + `tls`).
