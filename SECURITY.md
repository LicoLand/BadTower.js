# Security policy

Report vulnerabilities privately to the maintainers before disclosure —
use the repository's private security advisory contact, never a public
issue.

## Model

The Station sees only handles and packet bytes — never plaintext,
endpoint identity or session content. Security posture:

- Station admission credentials (`btm1`) are HMAC-bound to a random
  mailbox id and a first-binding deadline; verification is constant-time
  and every failure is an identical bare status.
- A mailbox binds one Ed25519 device key at first HELLO; other keys are
  refused. Revocation is an offline `btr1` token, idempotent, destructive.
- The Worker strips client-supplied internal headers and never reveals
  whether an unknown mailbox exists (404/401 shapes are uniform).
- The container runs read-only, capability-free, no-new-privileges; the
  only writable mount is the data volume.

## Out of scope

Endpoint authentication beyond the bound device key, traffic-content
inspection (impossible by design), and denial-of-service from a holder of
a valid credential against its own mailbox.
