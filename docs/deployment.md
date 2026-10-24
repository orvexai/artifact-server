# Deploy Artifact Server

Artifact Server supports local, single-server, Kubernetes, and managed-cloud deployments.

## Choose a deployment

| Deployment | Data layer | Detailed guide |
| --- | --- | --- |
| Cloudflare | D1 and R2 | [Cloudflare](../deploy/cloudflare/README.md) |
| Compact Compose | SQLite and one file volume | [Compose](../packaging/compose/README.md) |
| External-storage Compose | PostgreSQL and S3-compatible storage | [Compose](../packaging/compose/README.md) |
| Kubernetes | PostgreSQL and object storage | [Helm](../packaging/helm/artifact-server/README.md) |
| AWS | ECS, RDS, and S3 | [AWS Pulumi](../deploy/pulumi/aws/README.md) |
| Google Cloud | Cloud Run, Cloud SQL, and Cloud Storage | [Google Cloud Pulumi](../deploy/pulumi/gcp/README.md) |

## Configure the shared boundaries

Each remote deployment needs these boundaries:

1. Configure one HTTPS application origin.
2. Configure a separate wildcard content domain.
3. Configure WorkOS or one generic OIDC provider.
4. Admit team members through Artifact Server.
5. Store service credentials outside source control.
6. Back up the database and artifact files.
7. Pin release deployments to an immutable image digest.

The application origin serves Artifact Server, its API, and its MCP endpoint. The content domain serves untrusted artifact files.

## Select storage

Compact Compose uses one SQLite database and one file volume. Run only one application process with this data layer.

External-storage deployments use PostgreSQL and object storage. These deployments support replaceable application processes and horizontal scaling.

## Configure authentication

Local-owner access works only on an exact loopback origin. Do not use it for remote access.

Remote deployments use WorkOS or a generic OIDC provider. Network access and application authorization remain separate controls.

### Use a generic OIDC issuer for MCP

The issuer configured for browser login also protects `/mcp`. Agents present an
end-user access token, and the server records the person who obtained it. MCP
upload plans return short-lived, single-use file URLs that accept the declared
file bytes without forwarding the MCP access token. Every other API route still
requires an API key or a browser session. The
server never issues client credentials and never runs an authorization server of
its own.

The issuer must provide four things:

- an OpenID Connect discovery document at `<issuer>/.well-known/openid-configuration`;
- access tokens signed as JWTs with RS256 or ES256, verifiable against the
  published JWKS;
- the authorization code flow with S256 PKCE;
- an access token whose `aud` contains the exact `<ARTIFACT_SERVER_ORIGIN>/mcp`.

The audience is the one step an operator must configure. Providers do not bind a
resource URL on their own. In Keycloak, add a client scope with an audience
mapper whose included custom audience is that exact URL, and assign the scope to
the client the agents use. Okta sets the audience on a custom authorization
server. A provider that supports RFC 8707 resource indicators can bind it per
request instead.

Microsoft Entra ID cannot protect `/mcp` this way. Its v2.0 access tokens name
the API's client ID in `aud`, not a URL, and its userinfo endpoint accepts only
Microsoft Graph tokens. Entra installations keep browser login and use API keys
for MCP.

On first use, the token or the issuer's userinfo response must carry the
person's `email` with `email_verified: true`. A person who already signed in
through the browser is recognized by issuer and subject and needs neither.

Register the client the agents use in one of two supported ways:

- the issuer offers RFC 7591 dynamic client registration, its discovery document
  advertises `registration_endpoint`, and each client registers itself;
- an administrator registers one client in the issuer and gives its client ID to
  the agents that need it.

Artifact Server publishes RFC 9728 protected-resource metadata at
`/.well-known/oauth-protected-resource/mcp` naming the issuer, and answers an
unauthenticated MCP request with `401` and a `resource_metadata` challenge, so a
compliant client finds the issuer without further configuration.

Clients that cannot complete OAuth keep using administration-issued API keys.
Tokens that name another resource are refused. ID tokens and other JWTs that are
not access tokens are refused too: a JOSE `typ` other than `at+jwt` or `JWT`,
or an ID-token claim such as `nonce` or `at_hash`.

The same OIDC deployment can protect the HTTP API. It publishes RFC 9728
metadata at `/.well-known/oauth-protected-resource/api`, advertises the
configured issuer, and accepts access tokens whose audience names the API
resource. The default resource is `<ARTIFACT_SERVER_ORIGIN>/api`; configure an
issuer audience mapper or resource indicator for that URL. To use a different
resource URL, set `ARTIFACT_SERVER_OIDC_API_RESOURCE`. API and MCP tokens are
audience-bound independently. The API verifier uses the JWKS URI published by
issuer discovery. Set `ARTIFACT_SERVER_OIDC_API_JWKS_URI` only when the API
verifier must use a different JWKS endpoint; the browser and MCP verifiers
continue using the discovery document's JWKS URI. The API metadata issuer and
token issuer are `ARTIFACT_SERVER_OIDC_ISSUER`.

Cloud deployments pass these API OAuth settings as environment variables:

| Environment variable | Contract |
| --- | --- |
| `ARTIFACT_SERVER_OIDC_API_RESOURCE` | Optional API audience URL; defaults to `<ARTIFACT_SERVER_ORIGIN>/api`. |
| `ARTIFACT_SERVER_OIDC_API_JWKS_URI` | Optional API verifier JWKS override. It must use HTTPS; plain HTTP is allowed only for a local OIDC issuer (`localhost`, `127.0.0.1`, or `::1`). |

The server reads the issuer's discovery document at startup. If the issuer cannot
be reached, times out, or answers with an error or an unreadable document, the
server still starts, logs `discovery_failed`, and keeps retrying in the
background, starting at one second and backing off with jitter to thirty, as
well as whenever a request needs OAuth. Until discovery succeeds:

- `/ready` answers `503` with `components.identity` reporting
  `{"oauth": "discovering", "status": "unavailable"}`, so a rolling update
  waits instead of finishing onto replicas without OAuth; `/health` stays `200`;
- both protected-resource documents, `/.well-known/oauth-authorization-server`,
  `/mcp`, and OAuth bearers on `/api/` answer `503` with `Retry-After`;
- API keys and browser sessions keep working.

API OAuth, MCP OAuth, and the metadata documents then turn on in the running
process, without a restart, and the server logs that discovery succeeded. If
every replica restarts while the issuer is down, none becomes ready until it
returns.

A discovery document that contradicts the configuration is different: another
`issuer`, no authorization code flow, no S256 PKCE, or an endpoint that is not
HTTPS. The server logs `discovery_misconfigured`, keeps MCP and API OAuth off,
stays ready with `components.identity.oauth` set to `misconfigured`, and does
not retry. Correct the issuer configuration and restart.

### Manage access with issuer groups

By default an administrator admits each person by hand, and only the bootstrap
administrator email signs in to an empty installation. A generic OIDC
installation can instead take admission and roles from the issuer's group claim,
so access is managed where people already are:

| Setting | Helm value | Meaning |
| --- | --- | --- |
| `ARTIFACT_SERVER_OIDC_MEMBER_GROUPS` | `identity.oidcMemberGroups` | Groups whose people are admitted as members. |
| `ARTIFACT_SERVER_OIDC_ADMINISTRATOR_GROUPS` | `identity.oidcAdministratorGroups` | Groups whose people are admitted as administrators. |
| `ARTIFACT_SERVER_OIDC_GROUPS_CLAIM` | `identity.oidcGroupsClaim` | The claim that lists a person's groups. Defaults to `groups`. |

The environment variables take comma-separated lists; the Helm values take YAML
lists. Names are trimmed and compared exactly, including case. The policy is on
when either list names a group, and both lists require the OIDC issuer and
client. With none of these set, nothing changes.

While the policy is on, every browser sign-in and every MCP access token is
checked against it. The email must still be verified. Then:

- a person in an administrator group is an administrator;
- otherwise, a person in a member group is a member;
- otherwise the person is refused, and an existing member is deactivated, which
  also ends their sessions and revokes their personal API keys.

A role that differs from the current one is changed at once, so removing someone
from the administrator group demotes them on their next sign-in or MCP call.
Someone deactivated this way returns as the same member when they rejoin a
group. The bootstrap administrator email admits no one under the policy, and the
issuer is authoritative: removing the last administrator from the administrator
group leaves the installation without one until a member of that group signs
in. An open browser session follows its member's current role, but the issuer
is consulted only at sign-in and on MCP calls, so a group change reaches that
session through the person's next sign-in or MCP call.

The browser reads the claim from the ID token. MCP reads it from the access
token, or from the userinfo response when the token carries no email. A claim
that is present but is not a list of strings fails the sign-in as a provider
error. Because MCP checks groups on every call, give the access token both the
email and the groups claim; a lean token sends each call to userinfo.

In Keycloak:

1. Create the groups, for example `artifact-users` and `artifact-admins`, and
   add people to them.
2. In the client scope the Artifact Server client uses (the dedicated scope is
   fine), add a mapper of type **Group Membership** with token claim name
   `groups`, **Full group path** off, and **Add to ID token**,
   **Add to access token**, and **Add to userinfo** on. With the full path on,
   the claim says `/artifact-admins` and must be configured that way.
3. Configure the server:

   ```sh
   ARTIFACT_SERVER_OIDC_MEMBER_GROUPS=artifact-users
   ARTIFACT_SERVER_OIDC_ADMINISTRATOR_GROUPS=artifact-admins
   ```

`artifactserver config check` reports the active policy under
`configuration.oidcGroupRoles`.

### Sync members from a Keycloak directory

Group roles act when someone signs in. To have members exist before their first
sign-in, and to remove leavers without waiting for them to come back, also sync
the Keycloak directory:

```sh
artifactserver maintenance sync-directory --once --mode external-storage
```

One pass reads every configured group completely, then makes the installation's
human members match it:

- each enabled user with a verified email in an administrator group becomes an
  administrator, and in a member group a member;
- missing people are admitted, deactivated ones are restored, and roles are
  changed where they differ;
- every other active member is deactivated, which ends their sessions and
  revokes their personal API keys. Service API keys are not touched.

The pass reads the whole directory before it writes anything. A configured group
that does not exist, a token or HTTP error, a failed page, or a directory with
no eligible user stops the pass with a non-zero exit and changes nothing. A
successful pass prints one JSON line:
`{"groups":2,"directoryUsers":40,"admitted":1,"reactivated":0,"roleChanged":0,"deactivated":0,"unchanged":39,"skipped":0}`.
Display names come from first and last name, else the username, else the email;
an existing member keeps its display name. Synced members bind to their OIDC
subject at their first sign-in, by verified email, exactly as other members do.

| Setting | Helm value | Meaning |
| --- | --- | --- |
| `ARTIFACT_SERVER_OIDC_DIRECTORY_PROVIDER` | `identity.oidcDirectoryProvider` | `keycloak`, the only provider. The chart defaults it. |
| `ARTIFACT_SERVER_OIDC_DIRECTORY_CLIENT_ID` | `identity.oidcDirectoryClientId` | The confidential client the sync authenticates as. |
| `ARTIFACT_SERVER_OIDC_DIRECTORY_CLIENT_SECRET` or `_FILE` | `secret.keys.oidcDirectoryClientSecret` | Its client secret. |
| `ARTIFACT_SERVER_OIDC_DIRECTORY_KEYCLOAK_URL` | `identity.oidcDirectoryKeycloakUrl` | Optional. The Keycloak base URL the sync calls instead of the issuer host, such as `http://keycloak-service.keycloak.svc:8080`. Plain HTTP is accepted only for a Kubernetes `.svc` host, so the client secret travels unencrypted inside the cluster. Include any Keycloak path prefix such as `/auth`. |

These settings require the group lists above, and the issuer must have the form
`<base>/realms/<realm>`; the admin API is then `<base>/admin/realms/<realm>`.
The sync obtains a token with the client-credentials grant at the issuer's
discovered token endpoint.

After the members are reconciled, the same pass copies every Keycloak group,
subgroups included, with its direct members, keyed by the Keycloak group id.
Groups are shown by their full path, such as `/Engineering/Platform`. A rename
keeps the group; a group deleted in Keycloak is deleted here. If the group
listing fails, nothing changes; if one group's members cannot be read, that
group keeps its previous members and the pass continues. Copying a group grants
no access by itself. The client needs no permission beyond `view-users` and
`query-groups`. The sync prints a second JSON line, `{"groupSync": {...}}`.

In Keycloak, create a separate client for the sync:

1. Create an OpenID Connect client such as `artifact-server-directory` with
   **Client authentication** on and **Service accounts roles** on. Turn off the
   standard and direct-access flows; it never signs anyone in.
2. Under **Service account roles**, assign only the `realm-management` client
   roles `view-users` and `query-groups`.
3. Store the client secret in the Kubernetes Secret and name its key in
   `secret.keys.oidcDirectoryClientSecret`.

The configured groups are looked up by exact name among top-level groups.

The Helm chart enables the `<release>-sync-directory` CronJob as soon as
`identity.oidcDirectoryClientId` is set. It runs every ten minutes by default
(`directorySync.schedule`), never overlaps itself, and uses the same image,
service account, security context, environment, and Secret mounts as the
staging cleanup. It holds one Postgres connection while it runs, so raise
`configuration.postgresConnectionBudget` by one. `config check` reports the
directory under `configuration.oidcDirectory`.

## Back up the installation

Back up metadata and artifact files as one coordinated recovery set. Use the procedure in the selected deployment guide.

Do a restore test before the first production release. Then repeat the test after a storage or deployment change.
