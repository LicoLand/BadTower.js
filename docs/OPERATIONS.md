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
Private outputs may not land at arbitrary repository-relative paths:
`--dir`, `--out` and TLS material are refused inside the tree unless
they sit under `data/` or `secrets/` (both ignored by git and the
image); the documented place is `data/`.

## Revocation

```sh
npm run station -- revoke --dir ~/private/badtower --station https://station.example --mailbox HEX [--ca PEM]
```

## TLS (self-hosted)

```sh
npm run station -- tls --dir ~/private/badtower --ip 203.0.113.10 [--dns name]
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

## Plan and capacity configuration

| Variable | Meaning |
| --- | --- |
| `BADTOWER_PLAN` | `free` or `paid` (default `free`). Selects the platform limit set validated at startup — per-object storage 1 GB free / 10 GB paid, plus the request, duration and row ceilings listed in `COST.md`. |
| `BADTOWER_MAILBOX_CAPACITY_BYTES` | Per-mailbox storage cap (default `1000000000`). The station refuses to run when it exceeds the plan's per-object limit. The submit path additionally measures the real post-insert database size and maps `SQLITE_FULL` to the contract's transient `mailbox-full`. |

Both live in `apps/station/wrangler.jsonc` `vars` (and `.dev.vars` for
`wrangler dev`). The values trace to the official inputs table in
`COST.md`; change the plan there first when Cloudflare moves a limit.

## Health

```sh
npm run station -- health --station https://station.example [--ca PEM]
```

## Aggregate metrics

`GET /v1/metrics` returns the aggregate cost meters
(`badtower_worker_requests_total`, `badtower_do_requests_total`,
`badtower_do_active_ms_total`, `badtower_ws_messages_total`,
`badtower_rows_read_total`, `badtower_rows_written_total`,
`badtower_sqlite_bytes`) labelled only by closed `operation`,
`direction` and `plan` sets, in Prometheus text exposition. It is
operator-only:

```sh
curl -H "Authorization: Bearer $(cat <dir>/station.key)" \
  --cacert <dir>/tls/ca.crt https://station.example/v1/metrics
```

Values are per-isolate aggregates for reconciliation against
Cloudflare's own usage record, which remains authoritative (see
`COST.md` and `OPERATIONS-VISIBILITY.md`).

## Local development

The Worker refuses non-https requests. `wrangler dev` defaults to plain
http, so local development either runs the TLS path above or opts in
explicitly:

```sh
npx wrangler dev -c apps/station/wrangler.jsonc --var BADTOWER_ALLOW_PLAINTEXT:true
```

The flag is a development override only; the deployed configuration
ships `BADTOWER_ALLOW_PLAINTEXT: "false"`.

## Container

`Dockerfile` + `compose.yml` run `wrangler dev --local` (workerd) with
HTTPS from the mounted private CA, `--persist-to` on the `badtower-state`
volume, read-only root, dropped caps and no-new-privileges. The container
healthcheck runs `scripts/container-healthcheck.mjs`, which reads
`BADTOWER_HEALTHCHECK_URL` and `BADTOWER_HEALTHCHECK_CA` from the
deployment environment (compose injects the loopback URL and the mounted
`ca.crt`). Mount `./secrets/` with `.dev.vars`, `server.key`,
`server.crt`, `ca.crt` (from `init` + `tls`).
