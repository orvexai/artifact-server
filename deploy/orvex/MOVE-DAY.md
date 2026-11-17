# Artifact Server move-day steps

For Bring-up. Run only after the Team Leader's GO between steps. Print counts, statuses, object
names and sizes only. Never print secret values or credentials.

## Stage 1: Thursday 26 November 2026

### Carried at the move: confirmed names and path

| Name and OpenBao path | Owner | Reason |
|---|---|---|
| `oidc-directory-client-secret`, `apps/artifact-server/oidc` | C1-4 carry via QMK TL3 | Must match today's production Keycloak directory-sync client registration. |
| `bootstrap-admin-email`, `apps/artifact-server/oidc` | C1-4 carry via QMK TL3 | The app requires a valid address at startup; must equal today's because the first admin policy and the local-owner path use it. |

No values or hashes belong in this list. The move-day read token is limited to these carried properties.

### Stage 1 GO check

Stage-1 GO: bootstrap admin address present in the secret store and valid (checked by name, never printed).
Stage-1 GO: a wildcard HTTPRoute for the content domain is admitted (R12 new rule live) and the wildcard certificate is on Manchester (QMK C1-11).

### Stage 1 DNS flip

- **Owner: QMK's TL3.** After Artifact Server data is carried and checked, and before the Stage-1 GO is declared, TL3 records the previous Cloudflare values for both `artifacts.orvex.ai` and `*.houstonartifacts.com`.
- Before changing DNS, TL3 runs a direct Manchester-origin test with `curl --resolve` and the Origin CA root. Use the app-host HTTPS request and URL-reconstruction check below; do not print credentials or tokenized content URLs.
- TL3 changes the Cloudflare records for `artifacts.orvex.ai` and `*.houstonartifacts.com`; both must be **PROXIED**. The edge change applies in seconds to a few minutes; there is no client TTL wait. If rollback is needed, TL3 restores the two recorded previous values.
- After the flip, Bring-up performs read-only checks: resolve both names; make an HTTPS request to `artifacts.orvex.ai`; make an HTTPS request to one existing content host under `*.houstonartifacts.com`; confirm the certificate and HTTP responses. Record only results/statuses, never a tokenized content hostname or URL.
- For the forwarded-header check, use an existing authenticated read-only session to GET `/api/v1/artifacts/<readable-artifact-id>` directly at the Manchester origin with `curl --resolve` before the flip and through normal DNS after it. Inspect only JSON `links.artifact` and `links.management`; both must show the expected `https://artifacts.orvex.ai` origin. Do not print the response body, cookies, or authorization values. The app silently falls back to the request origin if forwarded proto/host do not match the configured origin (no status or log); compare the printed origin to the configured origin exactly, before and after the flip.

The URL-reconstruction check uses a throwaway test project and test artifact, not production content:

1. An existing Artifact Server owner creates a restricted test project and a single test artifact with non-sensitive content. Use a dedicated temporary Keycloak group and one throwaway OIDC test identity; assign that group the Viewer role and share only the restricted test project with it as Viewer. Confirm the test identity can see only that test project; if any other project is visible, stop and remove the test setup before proceeding.
2. Sign in as that test identity and run the read-only `GET /api/v1/artifacts/<test-artifact-id>` check above. Verify that both URL fields show exactly `https://artifacts.orvex.ai` as their origin. Record only the origin comparison result.
3. Delete the test artifact and restricted project; remove the temporary project share and group-role assignment; then delete the throwaway Keycloak identity and temporary group. Confirm the artifact, project, share, role assignment, identity, and group are absent. Do not print identity values, cookies, tokens, or tokenized URLs.

The test identity needs an existing installation owner to grant its Viewer group role; the app does not require that owner to be Daniel specifically. The move-day operator uses the authorized current owner, without printing the carried bootstrap address.

### GO check: re-resolve today's Keycloak

Hostname: `auth.eu-central-1.myidp.cloud`. On Wednesday 25 November and again on Thursday 26
November morning, record `date -u` and the complete sorted A-record set from a read-only DNS lookup.
Compare each answer with the prior recorded set. The baseline lookup was Tue 17 Nov 2026 at
18:30:58Z: `104.21.80.137`, `172.67.183.128`. Re-resolved Tue 17 Nov 2026 at 19:17:15Z;
the sorted A records were unchanged: `104.21.80.137`, `172.67.183.128`. ARIN RDAP at Tue 17 Nov 2026 18:35:19Z reports
both addresses as Cloudflare, Inc. (`CLOUDFLARENET`). If the set changes, open a one-line PR that
morning and tell QMK through the Team Leader before proceeding.

`app.yaml` lists `artifacts.orvex.ai` only. The wildcard hostname and HTTPRoute remain disabled until
the Platform R12 change for the registered content domain is live in a pin (platform #21); add both
before the Wed 25 pin. The content-domain certificate must also be on Manchester (QMK C1-11).

These are shared Cloudflare anycast addresses. A `/32:443` policy for both addresses lets every
site behind either address be reached from the Artifact Server namespace, not only Keycloak. The
rendered D107 `orvex-allow-internet` already allows every app namespace public internet egress
(`0.0.0.0/0` and `::/0`, except private, link-local, node, pod, service and LB-pool ranges) until
the egress gateway. The Artifact Server door documents the Keycloak address; it adds no reachability
and restricts none. No D107 rule is changed here.

If the addresses change at the wrong moment, sign-in to today's Keycloak breaks. The fallback is a
one-line PR to correct the recorded addresses, or stage 1 without Artifact Server sign-in; the
Captain decides on the day. Do not guess or widen the address set.

### Rehearsal handling

Do not restore data until the rehearsal no-outbound-secret and worker-suspended checks are merged
and verified. Immediately after the cutover, delete the rehearsal environment using MA-21 tooling;
if it is not ready, the platform engineer deletes the rehearsal by hand. The rehearsal has no
hostname and no external door. Its database is never archived.

After a rehearsal restore and before port-forwarding, scrub credential-bearing data from the
rehearsal database. Credential-bearing fields found in the schema (table.column only):

- `versions.content_token`
- `staged_upload_files.storage_token`
- `content_bootstraps.token_digest`, `content_bootstraps.content_token`
- `content_sessions.token_digest`, `content_sessions.content_token`
- `application_sessions.token_digest`, `application_sessions.csrf_digest`
- `managed_api_keys.secret_digest`
- `login_attempts.state_digest`, `login_attempts.code_verifier`
- `guest_review_invitations.token_digest`
- `guest_review_sessions.token_digest`, `guest_review_sessions.csrf_digest`
- `artifact_platform_sessions.token_digest`

In one transaction against only `artifactserver` in namespace `artifact-server-rehearsal`, rotate
all `versions.content_token` values to fresh random values to invalidate existing content URLs;
delete all staged upload file rows before their staging parent rows; and delete rows from
`content_bootstraps`, `content_sessions`, `application_sessions`, `managed_api_keys`,
`login_attempts`, `guest_review_invitations`, `guest_review_sessions`, and
`artifact_platform_sessions`. Print table names and row counts only. Do not copy production tokens or
any secret values to a file or command argument.

### Production hand-sync backup

After the production database data is loaded on Manchester and before stage 1 is declared done,
apply this one-time `Backup` manifest:

```yaml
apiVersion: postgresql.cnpg.io/v1
kind: Backup
metadata:
  name: artifact-server-stage-1-base
  namespace: artifact-server
spec:
  method: plugin
  cluster:
    name: artifact-server-db
  pluginConfiguration:
    name: barman-cloud.cloudnative-pg.io
```

Confirm both evidence lines before the Team Leader declares the stage done:

1. `kubectl -n artifact-server get backup artifact-server-stage-1-base -o jsonpath='{.status.phase}'`
   reports `completed`, and the current primary's instance log has the plugin upload-complete line.
2. QMK's TL3 or the Captain performs a list-only read of the exact backup folder in Backblaze and
   records object names and sizes. An empty or missing folder means STOP.

The by-hand base backup above still applies before stage 1 is declared done. The barman-cloud plug-in
and routine daily base-backup schedule remain deferred until the admin's ObjectStore `orvex-backup`
is live (orvex-apps PR G / MP-06) and app.yaml declares `backups: {postgres: true}`. Once enabled,
the daily schedule is 12:00 UTC, outside QMK's 23:30-07:00 UTC copy window. QMK's TL3 must receive
the database name, UTC start and expected size, with the Captain copied, before the first scheduled
base backup.

## Stage 2: Friday 27 November 2026

In the stage 2 change itself: remove external door (stage 2 change). Remove both production-only external address entries. Owner: TL; tracking bead `quornex-74w`. Confirm the new Manchester Keycloak issuer and directory URL
render, then remove the rehearsal immediately as above.
