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
app-host forwarded-header check: not done by decision (low impact); optional authenticated steps below.

### Stage 1 DNS flip

- **Owner: QMK's TL3.** After Artifact Server data is carried and checked, and before the Stage-1 GO is declared, TL3 records the previous Cloudflare values for both `artifacts.orvex.ai` and `*.houstonartifacts.com`.
- Before changing DNS, TL3 runs a direct Manchester-origin HTTPS test with `curl --resolve` and the Origin CA root. Request `/auth/login` on the app host and confirm a 302 redirect to Keycloak; do not print cookies or the full redirect URL/query.
- TL3 changes the Cloudflare records for `artifacts.orvex.ai` and `*.houstonartifacts.com`; both must be **PROXIED**. The edge change applies in seconds to a few minutes; there is no client TTL wait. If rollback is needed, TL3 restores the two recorded previous values.
- After the flip, Bring-up performs these read-only checks: resolve `artifacts.orvex.ai` and `*.houstonartifacts.com`; make an HTTPS request to the app host; GET `/auth/login` and confirm a 302 redirect to Keycloak (this proves reachability and the OIDC redirect only); make an HTTPS request to one content host through the public artifact route. Confirm the certificate and HTTP responses. Record only results/statuses, never a tokenized content hostname or URL; do not print cookies or the full redirect URL/query.

### OPTIONAL: authenticated app-host forwarded-header check

This check is not part of the Stage-1 plan. Run it only if QMK's TL3 insists; it requires a card to Daniel and a Hetzner-side Keycloak administrator. The temporary project is archived, not erased. The go-page line remains: “app-host forwarded-header check: not done by decision (low impact); optional authenticated steps below”.

The optional URL-reconstruction check uses one throwaway viewer identity and non-sensitive test content, never production content:

1. An authorized Keycloak administrator creates a temporary Keycloak group and one throwaway test identity, and puts only that identity in the group. Use Keycloak's one-time invitation/reset flow; do not record or print its email, password, invitation URL, or tokens. The Artifact Server owner waits for directory sync, locates the group in the app, and assigns its installation role as `viewer` (`PUT /api/v1/groups/<group-id>/role`, body `{"role":"viewer"}`). The owner creates one temporary project (`POST /api/v1/projects`, body `{"name":"MA-26 DNS check temporary"}`); new projects are restricted by default. Share only that project with the temporary group as Viewer (`PUT /api/v1/projects/<project-id>/groups/<group-name>`, body `{"role":"viewer"}`). In the app UI, upload one harmless text file to that project to create the throwaway artifact. Record resource IDs only in the move-day working record, not in a public log.
2. Sign in as the throwaway identity. In the app UI, verify that it can see only the temporary project and its one artifact; if it sees any other project or artifact, stop, do not run the header check, and proceed directly to cleanup. With that identity's session, request `GET /api/v1/artifacts/<test-artifact-id>` once directly against the Manchester origin before the DNS flip using `curl --resolve` and the Origin CA root, then again through normal DNS after the flip. Do not print the response body or session material; inspect only the scheme and host of `links.artifact` and `links.management`. Both must equal the configured `https://artifacts.orvex.ai` origin exactly. Record only pass/fail and the origin comparison. The mismatch is silent (no status, no log), so compare the printed origin to the configured origin EXACTLY, before and after the flip.
3. Clean up immediately after the post-flip check. As the owner, remove the project's group share (`DELETE /api/v1/projects/<project-id>/groups/<group-name>`), delete the artifact in the app UI (or `DELETE /api/v1/artifacts/<artifact-id>` with its current-version ID and a fresh idempotency key), and archive the temporary project (`POST /api/v1/projects/<project-id>/archive`). Then remove the group's Viewer installation role (`PUT /api/v1/groups/<group-id>/role`, body `{"role":null}`); in Keycloak, delete the throwaway identity and temporary group. Verify the artifact is no longer accessible, the project is archived and no longer in the active project list, and the share, group role, Keycloak identity, and Keycloak group are absent. Do not print identity values, cookies, tokens, or tokenized URLs.

**Cleanup limit:** Artifact Server exposes project archival, not permanent project deletion (`POST /api/v1/projects/:projectId/archive`); its database retains the archived project and deletion/audit records. Do not claim that no database record remains. If the card requires permanent erasure, do not create the test identity or project; use the fallback smoke checks. The app owner can grant the group role only while an installation Owner exists. The move-day operator must use the authorized current Owner; repo configuration does not identify that person. The carried production database already has its existing Owner, per the TL; `Administrators=owner` maps an identity in the Keycloak Administrators group to Owner at sign-in, but does not establish that Daniel is the carried Owner.

**Card for Daniel (only if QMK's TL3 insists):** “May the Artifact Server owner arrange a throwaway viewer test account on one throwaway artifact and delete both after the DNS check?” The account can see only one throwaway artifact in its restricted temporary project, during Thu 26 Nov around the DNS flip. An authorized Hetzner-side Keycloak administrator creates/deletes the identity and group; the Artifact Server owner assigns/removes the app-side group role and project share. The artifact is deleted and the project archived, with the retained database records described above.

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
