# 0029: OIDC discovery retries, and an undiscovered issuer holds readiness

**Status:** Accepted
**Date:** October 13, 2026

Supersedes the section "Discovery runs at startup, and a down issuer only turns
MCP OAuth off" of [0028: MCP OAuth through the configured OIDC issuer](0028-oidc-mcp-oauth.md).
Everything else in 0028 stands.

## Context

0028 read the issuer's discovery document once at startup and, on failure,
started the process with browser login and managed API keys only. On
2026-10-13 a rollout started pods while Keycloak discovery answered HTTP 503.
Every new pod logged `discovery_failed` and then ran with OAuth off for its
whole life: `/.well-known/oauth-protected-resource/api` and `/mcp` answered
404, OAuth bearers on `/api` and `/mcp` were refused, `artifactserver auth
login` reported that the server "does not advertise browser authorization", and
CLI refreshes failed. `/ready` stayed 200, so the rollout completed onto those
pods, and only a restart after Keycloak recovered fixed it.

One startup failure disabled five things at once: the API OAuth verifier, the
MCP OAuth verifier, both RFC 9728 protected-resource documents, the
authorization-server document, and the `resource_metadata` challenges on `/api`
and `/mcp`. Browser login was the exception, because its provider already
discovers lazily on every login until it succeeds once.

## Decision

Discovery is no longer a one-shot. A configured issuer is discovered by a
supervisor that keeps one state per process: `discovering`, `enabled`, or
`misconfigured`.

- **Startup** awaits the first attempt, so a healthy issuer starts the process
  with OAuth on exactly as before.
- **Transient failures** keep the state `discovering` and retry in the
  background for as long as the process lives. The delay ceiling starts at one
  second and doubles to thirty; each delay is drawn from the upper half of its
  ceiling, so replicas spread out and never spin.
- **Requests that need OAuth** may ask for an attempt now. At most one attempt
  is ever in flight, concurrent requests join it, and a request within two
  seconds of the previous attempt reads the state without contacting the
  issuer.
- **Success** turns on API OAuth, MCP OAuth, both protected-resource documents,
  the authorization-server document, and the `resource_metadata` challenges in
  the running process. Once on, OAuth never turns off again.

### Transient and permanent failures

A failure is permanent only when the issuer answered with a readable discovery
document that contradicts this installation: a different `issuer`, no
authorization code response type, no S256 PKCE, or an endpoint that is not
HTTPS (plain HTTP only for a local issuer). Waiting cannot fix those. They are
logged once as `discovery_misconfigured`, OAuth stays off exactly as 0028 left
it, the process stays ready, and nothing is retried.

Everything else is transient: a network error, a timeout, any non-2xx status
including redirects and 404, a body that is not JSON, and a document missing
required fields. Treating 404 and unreadable answers as transient errs toward
holding readiness, which keeps existing pods serving, rather than toward
completing a rollout onto pods without OAuth.

An issuer or API JWKS URL that is malformed in the configuration itself still
fails startup, as before.

### Readiness holds while the issuer is undiscovered

`/ready` adds an `identity` component beside the existing ones whenever a
generic OIDC issuer is configured:

```json
{"components": {"configuration": {...}, "database": {...}, "migrations": {...},
  "objectStorage": {...},
  "identity": {"latencyMilliseconds": 0, "oauth": "discovering", "status": "unavailable"}},
 "lifecycle": "ready", "status": "not_ready"}
```

While `oauth` is `discovering` the component is `unavailable` and `/ready`
answers 503. `enabled` and `misconfigured` are both `ready`. The component
reads the supervisor's state and never contacts the issuer, so the probe stays
fast. `/health` is unaffected, so liveness never kills a pod for an identity
provider outage.

The Helm chart's readiness probe already uses `/ready` and its liveness and
startup probes use `/health`. With `maxUnavailable: 0`, a rollout during an
issuer outage now waits on the first new pod while the existing pods keep
serving, and continues by itself once discovery succeeds.

### OAuth endpoints answer as temporarily unavailable

While `discovering`:

- `/.well-known/oauth-protected-resource/mcp`,
  `/.well-known/oauth-protected-resource/api`, and
  `/.well-known/oauth-authorization-server` answer 503 with the RFC 6749 body
  `{"error": "temporarily_unavailable", ...}`;
- `/mcp` answers the same 503 to any request that does not present a managed
  API key, including an unauthenticated one that would otherwise receive the
  `resource_metadata` challenge;
- an `/api/` request with a bearer that is not a managed API key answers 503
  with `IDENTITY_PROVIDER_UNAVAILABLE`.

Every such answer carries `Retry-After` (the seconds until the next background
attempt, at least one) and `Cache-Control: no-store`. A 404 or a 401 would
tell a client that this server has no OAuth, and clients cache that. Managed
API keys and browser sessions never need the issuer and keep working.

The CLI reads a 503 from the API metadata as "not connected to its identity
provider yet, try again shortly", both for `auth login` and when a refresh
fails, and keeps the stored grant instead of asking for a new login.

## Consequences

- A pod started during an issuer outage serves keys and sessions but is not
  ready; it becomes ready by itself within about thirty seconds of the issuer
  recovering, or sooner if a request needs OAuth.
- If every replica restarts while the issuer is down, none becomes ready, so
  the Service has no endpoints until the issuer returns, including for API-key
  and browser-session traffic that would have worked. That is the price of
  never routing to a replica whose OAuth contract is unknown, and it is
  bounded by the issuer's own outage.
- A permanently misconfigured issuer behaves as before: ready, OAuth off, one
  clear log line. Fixing it still needs a restart.
- Browser login keeps its own lazy discovery and is unchanged.
- The Cloudflare worker configures generic OIDC for browser login only, so it
  is unaffected.

## Rejected alternatives

### Fail startup when discovery fails

Kubernetes would crash-loop the new pods and back off, which also holds the
rollout, but compact and single-server installations would stop serving keys
and sessions for the length of any issuer outage, and the restart backoff would
delay recovery well past the issuer's return.

### Keep readiness green and only retry

OAuth would now recover on its own, but a rollout could still finish onto
replicas that refuse every OAuth client for an unknown time, which is exactly
what the incident did.

### Retry permanent misconfiguration too

A document that names another issuer does not become right by waiting, and
holding readiness on it would block every rollout of an installation whose
operators rely on API keys and browser login. It is logged as a configuration
error instead.
