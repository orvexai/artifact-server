import {
  createOrgRuntime,
  openExternalStorageDatabase,
  type ExternalStorageOrgConfig,
  type ExternalStorageRuntime,
  type ExternalStorageRuntimeConfig,
} from "./create-external-storage-runtime.js";
import {OrganizationRegistry, type OrganizationRecord} from
  "./organization-registry.js";
import {z} from "zod";
import {Effect} from "effect";
import {SqlClient} from "effect/unstable/sql/SqlClient";
import {createKeycloakOrganizationMembershipResolver} from "./organization-memberships.js";
import {PlatformSessions} from "./platform-sessions.js";

const maximumCachedOrganizations = 16;
const idleOrganizationMilliseconds = 5 * 60 * 1_000;
const organizationEvictionIntervalMilliseconds = 30_000;
// The verifier accepts installation-less bindings only for Orvex, and only
// when exp is no later than one hour after process start. The ordinary
// one-hour binding TTL makes this a bounded rolling-deployment transition.
const legacyInstallationlessBindingExpiresAt = Math.floor(Date.now() / 1_000) + 60 * 60;
const notFound = () => new Response("Not Found", {status: 404});

export interface OrganizationRouterOptions {
  readonly idleMilliseconds?: number;
  readonly evictionIntervalMilliseconds?: number;
}

interface CachedRuntime {
  activeRequests: number;
  lastUsedAt: number;
  readonly registryVersion: string;
  readonly securityFingerprint: string;
  readonly status: OrganizationRecord["status"];
  readonly runtime: ExternalStorageRuntime;
}

interface OpeningRuntime {
  readonly registryVersion: string;
  readonly promise: Promise<CachedRuntime>;
}

/** One shared pool and provider factory serving lazily opened org runtimes. */
export interface OrganizationRouter {
  readonly fetch: (request: Request) => Promise<Response>;
  close(): Promise<void>;
}

/** Start an organization registry router over one process's shared resources. */
export async function createOrganizationRouter(
  config: ExternalStorageRuntimeConfig,
  options: OrganizationRouterOptions = {},
): Promise<OrganizationRouter> {
  const database = await openExternalStorageDatabase(
    config,
    "artifact-server:organization-router",
  );
  const runtimes = new Map<string, CachedRuntime>();
  const retiredRuntimes = new Set<CachedRuntime>();
  const openingRuntimes = new Map<string, OpeningRuntime>();
  let closed = false;
  let evictionTimer: ReturnType<typeof setInterval> | undefined;
  try {
    const registry = new OrganizationRegistry(database);
    const platformSessions = new PlatformSessions(
      database,
        config.organizationMemberships ?? createKeycloakOrganizationMembershipResolver(
          (slug) => registry.find(slug),
          async (organization, identity) => database.run(Effect.gen(function*() {
            const sql = yield* SqlClient;
            const rows = yield* sql`SELECT EXISTS (
              SELECT 1 FROM external_identities identity
              JOIN installation_members member ON member.installation_id = identity.installation_id AND member.id = identity.member_id
              WHERE identity.installation_id = ${organization.id} AND identity.provider = ${identity.provider}
                AND identity.subject = ${identity.subject} AND (member.manual_deactivation = TRUE OR member.status = 'inactive')
            ) AS deactivated`;
            return rows[0]?.["deactivated"] === true;
          })),
        ),
    );
    await registry.ensureOrvex(config.installationId);
    const closeResources = async () => {
      if (closed) return;
      closed = true;
      if (evictionTimer !== undefined) clearInterval(evictionTimer);
      await Promise.allSettled([...openingRuntimes.values()].map(({promise}) => promise));
      const active = [...runtimes.values()];
      runtimes.clear();
      await Promise.all([
        ...active.map(({runtime}) => runtime.close()),
        ...[...retiredRuntimes].map(({runtime}) => runtime.close()),
        config.objectStorage.close?.(),
      ]);
      await database.close();
    };
    const runtimeFor = async (organization: OrganizationRecord) => {
      const securityFingerprint = JSON.stringify({
        admissionPolicy: organization.admissionPolicy,
        embedOrigins: organization.embedOrigins,
        routeId: organization.routeId,
        slug: organization.slug,
        status: organization.status,
      });
      const acquire = (entry: CachedRuntime): CachedRuntime | null => {
        if (entry.status !== "active") return null;
        entry.activeRequests += 1;
        entry.lastUsedAt = Date.now();
        runtimes.delete(organization.id);
        runtimes.set(organization.id, entry);
        return entry;
      };
      const cached = runtimes.get(organization.id);
      if (cached !== undefined) {
        if (BigInt(cached.registryVersion) > BigInt(organization.registryVersion)) {
          return cached.status === "active" ? acquire(cached) : null;
        }
        if (cached.registryVersion === organization.registryVersion) {
          return cached.securityFingerprint === securityFingerprint ? acquire(cached) : null;
        }
      }
      const opening = openingRuntimes.get(organization.id);
      if (opening !== undefined && BigInt(opening.registryVersion) >= BigInt(organization.registryVersion)) {
        return acquire(await opening.promise);
      }
      const admissionPolicy = organization.admissionPolicy === null
        ? null
        : {
          groupRoots: organization.admissionPolicy.groupRoots,
          seed: organization.admissionPolicy.seed.map(({role, selector, staff}) =>
            staff === undefined ? {role, selector} : {role, selector, staff}
          ),
        };
      if (admissionPolicy !== null && organization.admissionPolicy?.guestGroupPrefixes !== undefined) {
        Object.assign(admissionPolicy, {
          guestGroupPrefixes: organization.admissionPolicy.guestGroupPrefixes,
        });
      }
      const orgConfig: ExternalStorageOrgConfig = {
        admissionPolicy,
        bootstrapAdministratorEmail: organization.slug === "orvex"
          ? config.bootstrapAdministratorEmail
          : null,
        cookieRouteId: organization.routeId,
        contentTokenPrefix: `${organization.routeId}-`,
        embedOrigins: organization.embedOrigins,
        slug: organization.slug,
        issuePlatformSession: (identity, existingToken) => platformSessions.issue(identity, existingToken),
        allowLegacyEmbedBinding: organization.slug === "orvex",
        legacyEmbedBindingExpiresAt: legacyInstallationlessBindingExpiresAt,
      };
      if (organization.keycloakId !== null) {
        Object.assign(orgConfig, {keycloakOrganizationId: organization.keycloakId});
      }
      if (config.applicationOrigin !== undefined) {
        Object.assign(orgConfig, {
          applicationOrigin: new URL(`/o/${organization.slug}`, config.applicationOrigin).toString(),
        });
      }
      if (organization.slug === "orvex") {
        Object.assign(orgConfig, {bootstrapApiToken: config.apiToken});
      }
      // The configured Git history provider owns one Orvex installation
      // location. Tenant runtimes cannot claim or reuse that provider location.
      const runtimeConfig = organization.slug === "orvex"
        ? config
        : withoutGitHistory(config);
      const pending = createOrgRuntime(
        organization.id,
        orgConfig,
        runtimeConfig,
        database,
      ).then(async (runtime) => {
        // close() may race a lazy startup. Never publish a runtime after the
        // router has closed; close the just-created resources instead.
        if (closed) {
          await runtime.close();
          throw new Error("The organization router is closed.");
        }
        const current = runtimes.get(organization.id);
        if (current !== undefined && BigInt(current.registryVersion) >= BigInt(organization.registryVersion)) {
          await runtime.close();
          return current;
        }
        const newerOpening = openingRuntimes.get(organization.id);
        if (newerOpening !== undefined && BigInt(newerOpening.registryVersion) > BigInt(organization.registryVersion)) {
          await runtime.close();
          return newerOpening.promise;
        }
        const entry: CachedRuntime = {
          activeRequests: 0,
          lastUsedAt: Date.now(),
          registryVersion: organization.registryVersion,
          securityFingerprint,
          status: organization.status,
          runtime,
        };
        runtimes.set(organization.id, entry);
        if (current !== undefined) {
          if (current.activeRequests === 0) await current.runtime.close();
          else retiredRuntimes.add(current);
        }
        return entry;
      });
      const openingEntry = {registryVersion: organization.registryVersion, promise: pending};
      openingRuntimes.set(organization.id, openingEntry);
      try {
        return acquire(await pending);
      } finally {
        if (openingRuntimes.get(organization.id) === openingEntry) {
          openingRuntimes.delete(organization.id);
        }
      }
    };
    const evictIdle = async () => {
      await platformSessions.sweepExpired().catch(() => undefined);
      const now = Date.now();
      const idleMilliseconds = options.idleMilliseconds ?? idleOrganizationMilliseconds;
      const expired = [...runtimes.entries()].filter(([, entry]) =>
        entry.activeRequests === 0 &&
        now - entry.lastUsedAt >= idleMilliseconds,
      );
      await Promise.all(expired.map(async ([id, entry]) => {
        runtimes.delete(id);
        await entry.runtime.close();
      }));
      const evicted: CachedRuntime[] = [];
      while (runtimes.size > maximumCachedOrganizations) {
        const oldest = [...runtimes.entries()].find(([, entry]) =>
          entry.activeRequests === 0,
        );
        if (oldest === undefined) break;
        runtimes.delete(oldest[0]);
        evicted.push(oldest[1]);
      }
      await Promise.all(evicted.map(({runtime}) => runtime.close()));
    };
    evictionTimer = setInterval(() => {
      void evictIdle();
    }, options.evictionIntervalMilliseconds ?? organizationEvictionIntervalMilliseconds);
    evictionTimer.unref();
    return {
      close: closeResources,
      fetch: async (request) => {
        if (closed) return new Response("Service Unavailable", {status: 503});
        const sourceUrl = new URL(request.url);
        const contentHostRequest = contentTokenFromHost(request, config.contentDomain);
        const contentHost = contentHostRequest.isContentHost;
        if (!contentHost && sourceUrl.pathname === "/") {
          if (request.method !== "GET" && request.method !== "HEAD") return notFound();
          const token = platformCookie(request);
          const session = token === null ? null : await platformSessions.find(token, true);
          if (session === null) return new Response(null, {headers: {Location: "/auth/platform/login?returnTo=%2F"}, status: 302});
          const active = new Set((await registry.list()).filter(({status}) => status === "active").map(({slug}) => slug));
          const organizations = session.organizations.filter(({slug}) => active.has(slug));
          if (organizations.length === 0) {
            return new Response('<!doctype html><html><head><meta charset="utf-8"><title>Artifact Server</title></head><body><main><p>You don\'t belong to any organization yet.</p></main></body></html>', {headers: {"Content-Type": "text/html; charset=utf-8", "Cache-Control": "private, no-store"}});
          }
          const last = organizations.find(({slug}) => slug === session.lastOrg);
          if (organizations.length === 1 || last !== undefined) {
            const selected = organizations.length === 1 ? organizations[0] : last;
            return new Response(null, {headers: {Location: `/o/${selected?.slug}/`}, status: 302});
          }
          const choices = organizations.map(({displayName, slug}) =>
            `<li><a href="/o/${encodeURIComponent(slug)}/">${escapeHtml(displayName)}</a></li>`).join("");
          return new Response(`<!doctype html><html><head><meta charset="utf-8"><title>Choose organization</title></head><body><main><h1>Choose an organization</h1><ul>${choices}</ul></main></body></html>`, {headers: {"Content-Type": "text/html; charset=utf-8", "Cache-Control": "private, no-store"}});
        }
        if (!contentHost && (sourceUrl.pathname === "/auth/login" || sourceUrl.pathname === "/auth/platform/login")) {
          const returnTo = sourceUrl.searchParams.get("returnTo") ?? "/";
          const organization = await registry.find("orvex").catch(() => null);
          if (organization === null || organization.status !== "active") return notFound();
          const entry = await runtimeFor(organization);
          const target = new URL(request.url);
          target.pathname = "/auth/login";
          target.search = "";
          target.searchParams.set("returnTo", sourceUrl.pathname === "/auth/platform/login"
            ? "/__artifact_platform_login?returnTo=%2F"
            : returnTo);
          return entry.runtime.app.fetch(new Request(target, request));
        }
        if (!contentHost && sourceUrl.pathname === "/api/v1/platform/me/orgs" && request.method === "GET") {
          const token = platformCookie(request);
          const session = token === null ? null : await platformSessions.find(token, true);
          if (session === null) return notFound();
          const active = new Set((await registry.list()).filter(({status}) => status === "active").map(({slug}) => slug));
          return Response.json(session.organizations.filter(({slug}) => active.has(slug)), {headers: {"Cache-Control": "private, no-store"}});
        }
        if (!contentHost && sourceUrl.pathname === "/api/v1/platform/session/last-org" && request.method === "POST") {
          if (config.applicationOrigin !== undefined && request.headers.get("origin") !== new URL(config.applicationOrigin).origin) return notFound();
          if (request.headers.get("sec-fetch-site") !== "same-origin") return notFound();
          const token = platformCookie(request);
          if (token === null) return notFound();
          const session = await platformSessions.find(token);
          if (session === null) return notFound();
          let body: unknown;
          try { body = await request.json(); } catch { return notFound(); }
          const parsedBody = z.object({slug: z.string().min(1).max(40)}).strict().safeParse(body);
          if (!parsedBody.success) return notFound();
          if (!session.organizations.some(({slug}) => slug === parsedBody.data.slug)) return notFound();
          const organization = await registry.find(parsedBody.data.slug).catch(() => null);
          if (organization === null || organization.status !== "active") return notFound();
          const saved = await platformSessions.setLastOrg(token, parsedBody.data.slug);
          return saved ? new Response(null, {status: 204}) : notFound();
        }
        if (!contentHost && sourceUrl.pathname === "/api/v1/platform/session/logout" && request.method === "POST") {
          if (config.applicationOrigin !== undefined && request.headers.get("origin") !== new URL(config.applicationOrigin).origin) return notFound();
          if (request.headers.get("sec-fetch-site") !== "same-origin") return notFound();
          const token = platformCookie(request);
          if (token !== null) await platformSessions.logout(token).catch(() => undefined);
          const cookies = request.headers.get("cookie") ?? "";
          const values = new Map(cookies.split(";").flatMap((part) => {
            const index = part.indexOf("=");
            return index < 0 ? [] : [[part.slice(0, index).trim(), part.slice(index + 1).trim()] as const];
          }));
          const origin = config.applicationOrigin === undefined ? new URL(request.url).origin : new URL(config.applicationOrigin).origin;
          const organizations = await registry.list().catch(() => []);
          await Promise.all(organizations.filter((organization) => organization.status === "active").map(async (organization) => {
            try {
            const suffix = `-${organization.routeId}`;
            const csrf = values.get(`__Host-artifact_csrf${suffix}`) ?? values.get(`artifact_csrf${suffix}`);
            const hasSession = values.has(`__Host-artifact_session${suffix}`) || values.has(`artifact_session${suffix}`);
            if (!hasSession) return;
            if (csrf === undefined) return;
            const headers = new Headers({
              cookie: cookies,
              origin,
              "sec-fetch-mode": "same-origin",
              "sec-fetch-site": "same-origin",
              "x-csrf-token": csrf,
            });
            const entry = await runtimeFor(organization);
            const target = new URL(request.url);
            target.pathname = "/api/v1/session/logout";
            const response = await Promise.resolve(entry.runtime.app.fetch(new Request(target, {headers, method: "POST"})));
            void response;
            } catch {
              // Each org session is best effort; the platform logout always clears browser cookies.
            }
          }));
          const logoutHeaders = new Headers();
          logoutHeaders.append("Set-Cookie", "__Host-artifact_platform=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; Secure; SameSite=Lax");
          const sessionCookieNames = new Set<string>();
          for (const organization of organizations) {
            const suffix = `-${organization.routeId}`;
            for (const name of [`__Host-artifact_session${suffix}`, `__Host-artifact_csrf${suffix}`]) {
              sessionCookieNames.add(name);
            }
          }
          for (const name of values.keys()) {
            if (/^(?:__Host-artifact_(?:session|csrf)-[a-z0-9]{8}|artifact_(?:session|csrf)(?:-[a-z0-9]{8})?)$/u.test(name)) sessionCookieNames.add(name);
          }
          for (const name of sessionCookieNames) {
              logoutHeaders.append("Set-Cookie", `${name}=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Secure; SameSite=Lax`);
          }
          return new Response(null, {headers: logoutHeaders, status: 204});
        }
        let organization: OrganizationRecord | null = null;
        let route = contentHost
          ? null
          : organizationRoute(sourceUrl.pathname) ??
            rootOAuthMetadataRoute(sourceUrl.pathname) ??
            (sourceUrl.pathname === "/auth/callback"
              ? {path: sourceUrl.pathname, slug: "orvex"}
              : null) ??
            (sourceUrl.pathname === "/health" || sourceUrl.pathname === "/ready"
              ? {path: sourceUrl.pathname, slug: "orvex"}
              : null);
        if (contentHost) {
          if (contentHostRequest.token === null) return notFound();
          const prefixedRouteId = /^([a-z0-9]{8})-/u.exec(contentHostRequest.token)?.[1];
          let contentOrganization: OrganizationRecord | null;
          if (prefixedRouteId === undefined) {
            // Before tenancy was enabled in production, all issued unprefixed
            // capabilities belonged to Orvex. No other installation can have
            // a legacy unprefixed token to migrate or honor.
            contentOrganization = await registry.find("orvex").catch(() => null);
          } else {
            contentOrganization = await registry.findByRouteId(prefixedRouteId).catch(() => null);
            if (contentOrganization?.routeId !== prefixedRouteId) contentOrganization = null;
          }
          if (contentOrganization === null || contentOrganization.status !== "active") return notFound();
          organization = contentOrganization;
          route = {path: sourceUrl.pathname, slug: contentOrganization.slug};
        }
        if (route === null) {
          const legacy = legacyOrganizationPath(sourceUrl.pathname);
          if (legacy === null) return notFound();
          if (requestComesFromAnotherOrganization(request)) return notFound();
          return new Response(null, {
            headers: {Location: `/o/orvex${legacy}${sourceUrl.search}`},
            status: 308,
          });
        }
        organization ??= await registry.find(route.slug).catch(() => null);
        if (organization === null || organization.status !== "active") {
          return notFound();
        }
        let entry: CachedRuntime | null;
        try {
          entry = await runtimeFor(organization);
        } catch {
          if (closed) return new Response("Service Unavailable", {status: 503});
          return notFound();
        }
        if (entry === null) return notFound();
        let requestFinished = false;
        const finish = () => {
          if (requestFinished) return;
          requestFinished = true;
          entry.activeRequests = Math.max(0, entry.activeRequests - 1);
          entry.lastUsedAt = Date.now();
          if (entry.activeRequests === 0 && retiredRuntimes.delete(entry)) {
            void entry.runtime.close();
          }
          void evictIdle();
        };
        const target = new URL(request.url);
        target.pathname = route.path;
        try {
          const response = prefixOrganizationRedirect(
            await entry.runtime.app.fetch(new Request(target, request)),
            route.slug,
            config.applicationOrigin,
          );
          if (response.body === null) {
            finish();
            return response;
          }
          const reader = response.body.getReader();
          const body = new ReadableStream<Uint8Array>({
            cancel: async (reason) => {
              try {
                await reader.cancel(reason);
              } finally {
                finish();
              }
            },
            pull: async (controller) => {
              try {
                const chunk = await reader.read();
                if (chunk.done) {
                  controller.close();
                  finish();
                } else {
                  controller.enqueue(chunk.value);
                }
              } catch (cause) {
                controller.error(cause);
                finish();
              }
            },
          });
          return new Response(body, {
            headers: response.headers,
            status: response.status,
            statusText: response.statusText,
          });
        } catch (cause) {
          finish();
          throw cause;
        }
      },
    };
  } catch (cause) {
    await Promise.all([config.objectStorage.close?.(), database.close()]);
    throw cause;
  }
}

function withoutGitHistory(config: ExternalStorageRuntimeConfig): ExternalStorageRuntimeConfig {
  const {
    gitHistory,
    gitHistoryHealthProbe,
    gitHistoryProvider,
    ...remaining
  } = config;
  void gitHistory;
  void gitHistoryHealthProbe;
  void gitHistoryProvider;
  return remaining;
}

function organizationRoute(pathname: string): {readonly path: string; readonly slug: string} | null {
  const match = /^\/o\/([^/]+)(\/.*)?$/u.exec(pathname);
  if (match === null) return null;
  let slug: string;
  try {
    slug = decodeURIComponent(match[1] ?? "");
  } catch {
    return null;
  }
  return {path: match[2] || "/", slug};
}

function rootOAuthMetadataRoute(
  pathname: string,
): {readonly path: string; readonly slug: string} | null {
  const resource = /^\/.well-known\/oauth-protected-resource\/o\/([^/]+)\/(?:api|mcp)$/u.exec(pathname);
  if (resource !== null) {
    try {
      return {path: pathname, slug: decodeURIComponent(resource[1] ?? "")};
    } catch {
      return null;
    }
  }
  if (
    pathname === "/.well-known/oauth-authorization-server" ||
    pathname === "/.well-known/oauth-protected-resource/api" ||
    pathname === "/.well-known/oauth-protected-resource/mcp"
  ) return {path: pathname, slug: "orvex"};
  return null;
}

interface ContentHostToken {
  readonly isContentHost: boolean;
  readonly token: string | null;
}

function contentTokenFromHost(
  request: Request,
  contentDomain: string,
): ContentHostToken {
  const hostHeader = request.headers.get("host");
  if (hostHeader === null) return {isContentHost: false, token: null};
  let hostname: string;
  try {
    hostname = new URL(`http://${hostHeader}`).hostname.toLowerCase().replace(/\.$/u, "");
  } catch {
    return {isContentHost: false, token: null};
  }
  const normalizedDomain = contentDomain.toLowerCase().replace(/\.$/u, "");
  const suffix = `.${normalizedDomain}`;
  if (hostname !== normalizedDomain && !hostname.endsWith(suffix)) {
    return {isContentHost: false, token: null};
  }
  if (hostname === normalizedDomain) return {isContentHost: true, token: null};
  const label = hostname.slice(0, -suffix.length);
  if (label.includes(".") || label.length === 0) return {isContentHost: true, token: null};
  return {isContentHost: true, token: /^[A-Za-z0-9_-]{16,100}$/u.test(label) ? label : null};
}


function legacyOrganizationPath(pathname: string): string | null {
  return /^\/(?:api(?:\/|$)|mcp(?:\/|$)|review(?:\/|$))/u.test(pathname)
    ? pathname
    : null;
}

function requestComesFromAnotherOrganization(request: Request): boolean {
  const referer = request.headers.get("referer");
  if (referer === null) return false;
  try {
    const sourcePath = new URL(referer).pathname;
    const slug = /^\/o\/([^/]+)(?:\/|$)/u.exec(sourcePath)?.[1];
    return slug !== undefined && slug !== "orvex";
  } catch {
    return true;
  }
}

function platformCookie(request: Request): string | null {
  const value = request.headers.get("cookie")?.split(";").map((part) => part.trim())
    .find((part) => part.startsWith("__Host-artifact_platform="))?.slice("__Host-artifact_platform=".length);
  return value !== undefined && /^[A-Za-z0-9_-]{32,}$/u.test(value) ? value : null;
}

function escapeHtml(value: string): string {
  return value.replaceAll("&", "&amp;").replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;").replaceAll('"', "&quot;").replaceAll("'", "&#39;");
}

function prefixOrganizationRedirect(
  response: Response,
  slug: string,
  applicationOrigin: string | undefined,
): Response {
  const location = response.headers.get("location");
  if (location === null || applicationOrigin === undefined) return response;
  const trustedOrigin = new URL(applicationOrigin).origin;
  const target = new URL(location, trustedOrigin);
  if (target.origin !== trustedOrigin || target.pathname.startsWith("/o/")) {
    return response;
  }
  const headers = new Headers(response.headers);
  headers.set("location", `/o/${slug}${target.pathname}${target.search}${target.hash}`);
  return new Response(response.body, {
    headers,
    status: response.status,
    statusText: response.statusText,
  });
}
