# Artifact Server move-day steps

For Bring-up. Run only after the Team Leader's GO between steps. Print counts, statuses, object
names and sizes only. Never print secret values or credentials.

## Stage 1: Thursday 26 November 2026

### Carried at the move: confirmed names and path

| Name and OpenBao path | Owner | Reason |
|---|---|---|
| `oidc-directory-client-secret`, `apps/artifact-server/oidc` | C1-4 carry via QMK TL3 | Must match today's production Keycloak directory-sync client registration. |
| `bootstrap-admin-email`, `apps/artifact-server/oidc` | C1-4 carry via QMK TL3 | The app requires a valid address at startup; must equal today's because the first admin policy and the local-owner path use it. |
| `access-key-id`, `secret-access-key`, `apps/artifact-server/hetzner-copy-ro` | C1-4 carry via QMK TL3 (Wed 25) | Stage 1 storage copy reads the Hetzner bucket `artifact-server-storage`; read-only; revoked after Stage 1. |

No values or hashes belong in this list. The move-day read token is limited to these carried properties.

### Stage 1 Hetzner storage copy credential

After the C1-4 carry places the credential in Manchester OpenBao at `apps/artifact-server/hetzner-copy-ro`, QMK applies three temporary objects in namespace `artifact-server` under its named 8-hour go. These are Manchester writes and must not be added to `deploy/orvex`:

1. Before applying, read only the `pod-security.kubernetes.io/*` labels on namespace `artifact-server`. Require `enforce=restricted` or `baseline`, `audit=restricted`, and `warn=restricted`; record the enforce value. If the namespace is not managed or these labels fail, STOP.
2. **Verify by name before apply:** read `NetworkPolicy/orvex-allow-object-storage` in namespace `artifact-server`. Confirm its selector matches the Job labeled `app.kubernetes.io/name=artifact-server`, and its egress admits the RGW endpoint from the OBC ConfigMap's `BUCKET_HOST` and `BUCKET_PORT`. If the policy is absent or either check fails, STOP before applying any objects.
3. From [`docs/move-day/stage1-artifact-server-copy-manifests.yaml`](../../docs/move-day/stage1-artifact-server-copy-manifests.yaml), apply only the first two documents, the `ExternalSecret` and dedicated `ServiceAccount`; do not apply the Job yet. Wait for `ExternalSecret/hetzner-copy-ro` to become Ready and confirm Secret `hetzner-copy-ro` exists by name. Quiesce the source before proceeding. Then apply only the `Job` document. These hand-applied objects are not part of the `deploy/orvex` GitOps tree. The ExternalSecret uses `SecretStore` `orvex-secrets`, with `creationPolicy: Owner`, mapping `artifact-server/hetzner-copy-ro` properties `access-key-id` and `secret-access-key` to Secret `hetzner-copy-ro`.
4. The Job reads source keys from `hetzner-copy-ro` and destination keys from the Rook OBC Secret `artifact-server-storage` through individual `secretKeyRef`s. It reads `BUCKET_NAME`, `BUCKET_HOST`, and `BUCKET_PORT` from the same-name OBC ConfigMap through individual `configMapKeyRef`s. Bring-up confirms the OBC Secret and ConfigMap names by name only before freezing the apply copy. The source remote is read-only to Hetzner bucket `artifact-server-storage`; the target bucket name is generated and comes from the ConfigMap. `RCLONE_CONFIG_SRC_*` and `RCLONE_CONFIG_DST_*` variables keep the source and destination credentials separate.
5. The Job uses `docker.io/rclone/rclone:1.76.0@sha256:075cf0e4e0f623996646cfb8a434c71cb4fcfe75bbbe27ccbb296ca04a7cd260`, the `linux/amd64` image manifest resolved anonymously from Docker Hub on 2026-11-23. It carries `app.kubernetes.io/name=artifact-server`; `orvex-allow-object-storage` permits its egress to the in-cluster RGW. `orvex-allow-internet` covers the public Hetzner S3 endpoint (D107).

Before accepting the copy, Bring-up must compare the final source and destination object counts and total bytes in the Job status. Require the quiesced source's before and after counts and bytes to match, and the destination's final counts and bytes to match the source's final counts and bytes. If any count or byte total differs, do not accept the copy.

Delete the Job, dedicated ServiceAccount, and `ExternalSecret` immediately after the copy; delete Secret `hetzner-copy-ro`; and show all four objects are gone. Keep the Rook-owned OBC Secret and ConfigMap.

### Stage 1 copy credential cleanup

After the Stage 1 copy check is accepted, run these revocation steps in order (R1-R4); record each line with `date -u` on the move record. Revocation is the Way Back's last step too: if Stage 1 is rolled back, R1-R4 still run.

1. **R1 — Hetzner MyIDP seat.** QMK's named go authorizes the Hetzner-side operator to run `radosgw-admin user rm --uid=artifact-server-copy-ro --purge-keys`, revoking every copy of the key. Show `user info` failing.
2. **R2 — QMK.** Restore the H1(c) saved bucket policy, or run DeleteBucketPolicy if it was "none" (H3 pod pattern, owner key in-cluster). Show the Sid list without `QmkStage1CopyReadOnly`.
3. **R3 — Hetzner MyIDP seat, then Quornex.** On Hetzner, run `bao kv metadata delete -mount=platform artifact-server/hetzner-copy-ro`. On Manchester, Quornex runs `bao kv metadata delete -mount=apps artifact-server/hetzner-copy-ro` and deletes the temporary Job, dedicated ServiceAccount, ExternalSecret, and generated Secret; show all four objects and both paths are gone. Each OpenBao metadata deletion requires a dedicated token with `delete` on `apps/metadata`; neither the carry token nor the hosted-namespace token has that capability.
4. **R4 — QMK.** Delete policy `qmk-rgw-ro-mint` and remove the H6 line from any kept carry policy.

### Stage 1 GO check

Stage-1 GO: bootstrap admin address present in the secret store and valid (checked by name, never printed).
Stage-1 GO: a wildcard HTTPRoute for the content domain is admitted (R12 new rule live) and the wildcard certificate is on Manchester (QMK C1-11).
app-host forwarded-header check: not done by decision (low impact); optional authenticated steps below.
Stage-1 GO (C1-14): before Stage 1, verify by name that MP-06 is live on Manchester; ObjectStore `orvex-backup` and Secret `backup-b2` are present; production `app.yaml` declares `backups: {postgres: true}` (orvex-apps #17 / MA-34); and the environment's own no-delete B2 key from MP-59 has been copied into OpenBao by MP-56. If any of these four prerequisites is false on Wednesday 25 November evening, Stage 1 does not start Thursday 26 November. The Captain takes the date change to QMK; nothing is waived.

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

### Production hand-sync backup (C1-14; required before each stage is declared done)

The production configuration has no usable by-hand base backup until all four Stage-1 prerequisites below are live and the backup component is enabled. Do not apply a `Backup` before then. The Stage-1 check is by resource name only; never print or record credentials or secret values:

1. MP-06 is live on Manchester. MP-06 PR #33 is merged to dev on Thursday 19 November; it is live only through pin 3, Thursday afternoon at the earliest, with QMK's and the Captain's word.
2. ObjectStore `orvex-backup` and Secret `backup-b2` are present. The admin ExternalSecret `orvex-backup-b2` is their sole writer.
3. Production `app.yaml` declares `backups: {postgres: true}`; this is orvex-apps #17 / MA-34, which waits for MP-06.
4. The environment's own no-delete B2 key is available: MP-59 is due Wednesday 25 November 18:00Z, and MP-56 copies it into OpenBao only after MP-59.

If any prerequisite is false on Wednesday 25 November evening, Stage 1 does not start Thursday 26 November. The Captain takes the date change to QMK. No prerequisite is waived.

The backup component is a prerequisite for the Stage-1 Backup. It is enabled in `deploy/orvex/production/kustomization.yaml` after orvex-apps MA-34 #17 merged. After the production database data is loaded on Manchester and all four prerequisites are confirmed, the component patches the Cluster and adds the daily `ScheduledBackup`:

```yaml
- ../components/backup
```

The component patches the Cluster with the barman-cloud WAL-archiver plug-in and adds its scheduled backup. Do not apply the Stage-1 `Backup` until the component is present in the production render and the Cluster shows the plug-in; then apply this one-time manifest:

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

Confirm both evidence lines before the Team Leader declares Stage 1 done:

1. `kubectl -n artifact-server get backup artifact-server-stage-1-base -o jsonpath='{.status.phase}'`
   reports `completed`, and the current primary's instance log has the plugin upload-complete line.
2. QMK's TL3 or the Captain performs a list-only read of the exact backup folder in Backblaze and
   records object names and sizes. An empty or missing folder means STOP.

The production Cluster's barman-cloud plug-in and routine daily base-backup schedule remain deferred until the admin's ObjectStore `orvex-backup` is live (MP-06) and production `app.yaml` declares `backups: {postgres: true}` (MA-34). Once enabled, the daily schedule is 12:00 UTC, outside QMK's 23:30-07:00 UTC copy window. QMK's TL3 must receive the database name, UTC start and expected size, with the Captain copied, before the first scheduled base backup.

## Stage 2: Friday 27 November 2026

Before Stage 2 is declared done, take a fresh by-hand base backup because the data has changed since Stage 1. This follows the Captain's 16 November C1-14 rule, as read by the Apps TL. The backup component remains a prerequisite to be added to PR #86 in a separate commit after merged orvex-apps MA-34 #17; confirm it is enabled in production and that the Cluster shows the plug-in. Recheck that ObjectStore `orvex-backup` and Secret `backup-b2` are still present by resource name; do not print or record credentials or secret values. Use the same method as Stage 1, changing only the Backup metadata name to `artifact-server-stage-2-base`:

```yaml
apiVersion: postgresql.cnpg.io/v1
kind: Backup
metadata:
  name: artifact-server-stage-2-base
  namespace: artifact-server
spec:
  method: plugin
  cluster:
    name: artifact-server-db
  pluginConfiguration:
    name: barman-cloud.cloudnative-pg.io
```

Before the Team Leader declares Stage 2 done, confirm both evidence lines:

1. `kubectl -n artifact-server get backup artifact-server-stage-2-base -o jsonpath='{.status.phase}'`
   reports `completed`, and the current primary's instance log has the plugin upload-complete line.
2. QMK's TL3 or the Captain performs a list-only read of that backup folder in Backblaze and records
   object names and sizes. An empty or missing folder means STOP.

In the stage 2 change itself: remove external door (stage 2 change). Remove both production-only external address entries. Owner: TL; tracking bead `quornex-74w`. Confirm the new Manchester Keycloak issuer and directory URL
render, then remove the rehearsal immediately as above.
