import {
  createOrgRuntime,
  openExternalStorageDatabase,
  type ExternalStorageOrgConfig,
  type ExternalStorageRuntime,
  type ExternalStorageRuntimeConfig,
} from "./create-external-storage-runtime.js";
import {OrganizationRegistry, type OrganizationRecord} from
  "./organization-registry.js";

const maximumCachedOrganizations = 16;
const idleOrganizationMilliseconds = 5 * 60 * 1_000;
const notFound = () => new Response("Not Found", {status: 404});

interface CachedRuntime {
  activeRequests: number;
  lastUsedAt: number;
  readonly runtime: ExternalStorageRuntime;
}

/** One shared pool and provider factory serving lazily opened org runtimes. */
export interface OrganizationRouter {
  readonly fetch: (request: Request) => Promise<Response>;
  close(): Promise<void>;
}

/** Start an organization registry router over one process's shared resources. */
export async function createOrganizationRouter(
  config: ExternalStorageRuntimeConfig,
): Promise<OrganizationRouter> {
  const database = await openExternalStorageDatabase(
    config,
    "artifact-server:organization-router",
  );
  const runtimes = new Map<string, CachedRuntime>();
  let closed = false;
  let evictionTimer: ReturnType<typeof setInterval> | undefined;
  try {
    const registry = new OrganizationRegistry(database);
    await registry.ensureOrvex(config.installationId);
    const closeResources = async () => {
      if (closed) return;
      closed = true;
      if (evictionTimer !== undefined) clearInterval(evictionTimer);
      const active = [...runtimes.values()];
      runtimes.clear();
      await Promise.all([
        ...active.map(({runtime}) => runtime.close()),
        config.objectStorage.close?.(),
      ]);
      await database.close();
    };
    const runtimeFor = async (organization: OrganizationRecord) => {
      const cached = runtimes.get(organization.id);
      if (cached !== undefined) {
        cached.lastUsedAt = Date.now();
        runtimes.delete(organization.id);
        runtimes.set(organization.id, cached);
        return cached;
      }
      const orgConfig: ExternalStorageOrgConfig = organization.slug === "orvex"
        ? {bootstrapApiToken: config.apiToken, cookieRouteId: organization.routeId}
        : {cookieRouteId: organization.routeId};
      const runtime = await createOrgRuntime(
        organization.id,
        orgConfig,
        config,
        database,
      );
      const entry = {activeRequests: 0, lastUsedAt: Date.now(), runtime};
      runtimes.set(organization.id, entry);
      return entry;
    };
    const evictIdle = async () => {
      const now = Date.now();
      const expired = [...runtimes.entries()].filter(([, entry]) =>
        entry.activeRequests === 0 &&
        now - entry.lastUsedAt >= idleOrganizationMilliseconds,
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
    }, 30_000);
    evictionTimer.unref();
    return {
      close: closeResources,
      fetch: async (request) => {
        if (closed) return new Response("Service Unavailable", {status: 503});
        const sourceUrl = new URL(request.url);
        const route = organizationRoute(sourceUrl.pathname) ??
          await organizationCallbackRoute(request, sourceUrl.pathname, registry);
        if (route === null) {
          const legacy = legacyOrganizationPath(sourceUrl.pathname);
          if (legacy === null) return notFound();
          return new Response(null, {
            headers: {Location: `/o/orvex${legacy}${sourceUrl.search}`},
            status: 308,
          });
        }
        const organization = await registry.find(route.slug).catch(() => null);
        if (organization === null || organization.status !== "active") {
          return notFound();
        }
        const entry = await runtimeFor(organization);
        entry.activeRequests += 1;
        entry.lastUsedAt = Date.now();
        const target = new URL(request.url);
        target.pathname = route.path;
        try {
          const response = await entry.runtime.app.fetch(new Request(target, request));
          return prefixOrganizationRedirect(response, route.slug, config.applicationOrigin);
        } finally {
          entry.activeRequests -= 1;
          entry.lastUsedAt = Date.now();
          await evictIdle();
        }
      },
    };
  } catch (cause) {
    await Promise.all([config.objectStorage.close?.(), database.close()]);
    throw cause;
  }
}

/** OAuth providers return to the shared callback; its org-scoped handshake cookie selects the runtime. */
async function organizationCallbackRoute(
  request: Request,
  pathname: string,
  registry: OrganizationRegistry,
): Promise<{readonly path: string; readonly slug: string} | null> {
  if (pathname !== "/auth/callback") return null;
  const cookieNames = new Set((request.headers.get("cookie") ?? "")
    .split(";")
    .map((cookie) => cookie.trim().split("=", 1)[0] ?? ""));
  const organizations = await registry.list();
  const matched = organizations.filter((organization) =>
    organization.status === "active" && (
      cookieNames.has(`__Host-artifact_login-${organization.routeId}`) ||
      cookieNames.has(`artifact_login-${organization.routeId}`)
    ),
  );
  const organization = matched.at(0);
  return matched.length === 1 && organization !== undefined
    ? {path: pathname, slug: organization.slug}
    : null;
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

function legacyOrganizationPath(pathname: string): string | null {
  return /^\/(?:api(?:\/|$)|mcp(?:\/|$)|review(?:\/|$))/u.test(pathname)
    ? pathname
    : null;
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
