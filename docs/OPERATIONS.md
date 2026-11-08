# Operations

This is a source-level runbook. It does not assert that a public instance has
been deployed or is operated. The checked-in Wrangler routes use non-routable
placeholder hostnames and must not be treated as production destinations.

## Verification and deployment preparation

1. Run `npm run check` against the exact source candidate.
2. Create a dedicated private directory with an existing owner-only parent.
3. Run
   `npm run secrets:bootstrap -- --target-dir <private-dir> --confirm bootstrap`
   once. The command refuses pre-existing output files and creates an operator
   token, its digest, capability keys, handle keys, and local variables with
   owner-only permissions.
4. Replace the placeholder route patterns and independently configure real
   DNS, certificates, the operator mTLS policy, WAF/rate limiting,
   spending controls, and monitoring in the target Cloudflare account.
5. Re-run repository verification after changing configuration. Confirm the
   external edge-result mapping against the actual Cloudflare runtime; local
   synthetic metadata is not deployment evidence.
6. If explicitly authorized to deploy, run
   `npm run cloudflare:deploy -- <private-dir>`.

The deploy script first validates owner-only material, exact disjoint secret
schemas, disabled `workers.dev` and preview URLs, and one real non-wildcard
route per Worker. It then invokes Wrangler separately with the data-only and
operator-only secret files.
It does not generate or rotate secrets, configure an account, create DNS, set
edge identity policy, configure WAF, or prove successful operation. Because
the two deploy invocations are sequential, failure of the second can leave
versions temporarily different; deployment coordination remains an operator
responsibility.

## Routine service-local operation

- Use a separate invitation and client Ed25519 key pair for each independent
  client scope. Delete the invitation after successful exchange.
- Retain the opaque invitation id needed for exact status and revocation; the
  service intentionally has no enumeration endpoint.
- Treat `429` and transient capacity outcomes as bounded overload and back off
  with jitter. Platform shedding is approximate; the `AccessGrant` transaction
  is the exact replay and budget authority.
- Use `/healthz` only for fixed data-entrypoint liveness. Use `/readyz` only
  through the restricted operator origin and both operator gates. Neither is
  endpoint, delivery, or deployment proof.
- Observe only aggregate categorical outcomes. Do not collect credentials,
  selectors, handles, IDs, request URLs or headers, protected packets,
  individual packet sizes, exception text, or Durable Object rows.

## Rotation and revocation

`npm run secrets:rotate -- --target-dir <private-dir> --confirm rotate`
advances the capability and handle key slots in existing validated private
material. It retains existing capability verification keys and a bounded set
of unexpired handle slots. The runtime accepts at most four capability keys;
plan retirement before exhausting that bound. Rotation changes local material
only; applying it to either Worker is a separate, explicit action.

The rotation command does not change the `bto1` operator token. Suspected
operator-token exposure therefore requires explicit replacement of the token
and its digest, followed by coordinated secret application. Do not silently
reuse bootstrap as an in-place rotation command.

For access-capability or client-key exposure, revoke every affected exact
invitation id. If both a `bta2` capability and its client private key are
compromised, requests remain possible until revocation or expiry. If a
capability or handle authentication key is compromised, stop issuance and
dispatch, identify the affected key slot and grants using private operational
records, retire or replace the material deliberately, and reissue affected
credentials. The repository provides no global grant enumeration or automatic
incident migration.

## Incident boundary

1. Stop invitation issuance and, when necessary, disable the affected ingress
   through the external account controls.
2. Revoke known affected grant ids and replace compromised material explicitly.
3. Verify both Worker configurations and edge policies before restoring
   access.
4. Preserve only redacted, content-free timing, categorical status, artifact
   digest, and configuration-version evidence.

Never copy private material, protected packets, raw logs, request metadata,
Durable Object rows, account identifiers, or user data into an issue, source
tree, fixture, or public incident report.

## Retention, deletion, and recovery

Invitation and grant state is disposable and can be recreated by issuing new
invitations. Relay packets have a one-hour application retention window;
claims and operation replay records have five-minute windows. Bounded alarms
remove expired state incrementally, while packet references required for a
live streamed replay are retained until the reference expires.

This relay is not backup storage. Provider backup, restore, Durable Object
deletion, account recovery, and disaster recovery are outside the application
API and have not been demonstrated by this repository. Any such action must
preserve the same privacy boundary.
