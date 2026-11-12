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
const organizationEvictionIntervalMilliseconds = 30_000;
const notFound = () => new Response("Not Found", {status: 404});

export interface OrganizationRouterOptions {
  readonly idleMilliseconds?: number;
  readonly evictionIntervalMilliseconds?: number;
}

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
  options: OrganizationRouterOptions = {},
): Promise<OrganizationRouter> {
  const database = await openExternalStorageDatabase(
    config,
    "artifact-server:organization-router",
  );
  const runtimes = new Map<string, CachedRuntime>();
  const openingRuntimes = new Map<string, Promise<CachedRuntime>>();
  let closed = false;
  let evictionTimer: ReturnType<typeof setInterval> | undefined;
  try {
    const registry = new OrganizationRegistry(database);
    await registry.ensureOrvex(config.installationId);
    const closeResources = async () => {
      if (closed) return;
      closed = true;
      if (evictionTimer !== undefined) clearInterval(evictionTimer);
      await Promise.allSettled(openingRuntimes.values());
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
      const opening = openingRuntimes.get(organization.id);
      if (opening !== undefined) return opening;
      const admissionPolicy = organization.admissionPolicy === null
        ? null
        : {
          groupRoots: organization.admissionPolicy.groupRoots,
          seed: organization.admissionPolicy.seed,
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
        slug: organization.slug,
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
      const pending = createOrgRuntime(
        organization.id,
        orgConfig,
        config,
        database,
      ).then(async (runtime) => {
        // close() may race a lazy startup. Never publish a runtime after the
        // router has closed; close the just-created resources instead.
        if (closed) {
          await runtime.close();
          throw new Error("The organization router is closed.");
        }
        const entry = {activeRequests: 0, lastUsedAt: Date.now(), runtime};
        runtimes.set(organization.id, entry);
        return entry;
      });
      openingRuntimes.set(organization.id, pending);
      try {
        return await pending;
      } finally {
        if (openingRuntimes.get(organization.id) === pending) {
          openingRuntimes.delete(organization.id);
        }
      }
    };
    const evictIdle = async () => {
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
        const route = organizationRoute(sourceUrl.pathname) ??
          rootOAuthMetadataRoute(sourceUrl.pathname) ??
          (sourceUrl.pathname === "/auth/callback"
            ? {path: sourceUrl.pathname, slug: "orvex"}
            : null) ??
          (sourceUrl.pathname === "/health" || sourceUrl.pathname === "/ready"
            ? {path: sourceUrl.pathname, slug: "orvex"}
            : null);
        if (route === null) {
          const legacy = legacyOrganizationPath(sourceUrl.pathname);
          if (legacy === null) return notFound();
          if (requestComesFromAnotherOrganization(request)) return notFound();
          return new Response(null, {
            headers: {Location: `/o/orvex${legacy}${sourceUrl.search}`},
            status: 308,
          });
        }
        const organization = await registry.find(route.slug).catch(() => null);
        if (organization === null || organization.status !== "active") {
          return notFound();
        }
        let entry: CachedRuntime;
        try {
          entry = await runtimeFor(organization);
        } catch {
          if (closed) return new Response("Service Unavailable", {status: 503});
          return notFound();
        }
        entry.activeRequests += 1;
        entry.lastUsedAt = Date.now();
        let requestFinished = false;
        const finish = () => {
          if (requestFinished) return;
          requestFinished = true;
          entry.activeRequests = Math.max(0, entry.activeRequests - 1);
          entry.lastUsedAt = Date.now();
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
