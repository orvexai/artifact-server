import {artifactServerRouteUrl} from "../core/server-address.js";
import {z} from "zod";

const installationRoute = "/api/v1/installation";
const organizationInstallationPath = /^\/o\/([a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?)\/api\/v1\/installation$/u;
const resourceMetadataDocumentSchema = z.object({resource: z.url()}).passthrough();

export interface CliApiDiscovery {
  readonly apiBasePath: string;
  readonly metadataUrl: URL;
  readonly resource: URL;
}

/** Discover the API audience and a same-origin tenant API path from its challenge. */
export async function discoverCliApi(
  address: string,
  initialBasePath = "",
): Promise<CliApiDiscovery> {
  const origin = new URL(address).origin;
  let apiBasePath = initialBasePath;
  let response = await probeInstallation(origin, apiBasePath);
  if (response.status === 308) {
    const location = response.headers.get("location");
    await response.body?.cancel();
    if (location === null) throw new Error(`API discovery at ${response.url} returned HTTP 308 without Location.`);
    const target = new URL(location, origin);
    const match = organizationInstallationPath.exec(target.pathname);
    if (target.origin !== origin || match === null || target.search !== "" || target.hash !== "") {
      throw new Error(`API discovery at ${response.url} refused unsafe redirect to ${target.toString()}.`);
    }
    apiBasePath = `/o/${match[1]}`;
    response = await probeInstallation(origin, apiBasePath);
  }
  if (response.status !== 401) {
    const status = response.status;
    const url = response.url;
    await response.body?.cancel();
    throw new Error(`API discovery at ${url} returned HTTP ${status}; expected an authentication challenge.`);
  }
  const challenge = response.headers.get("www-authenticate") ?? "";
  await response.body?.cancel();
  const metadataUrl = resourceMetadataUrl(challenge, origin, response.url);
  if (
    (metadataUrl.protocol !== "https:" && !isLoopbackHttpUrl(metadataUrl))
    || metadataUrl.origin !== origin
    || metadataUrl.username !== ""
    || metadataUrl.password !== ""
  ) {
    throw new Error(
      `Authentication challenge at ${response.url} advertised an unsafe resource_metadata URL ${metadataUrl.toString()}; it must use HTTPS (or HTTP for a loopback profile) on ${origin}.`,
    );
  }
  const metadataResponse = await fetch(metadataUrl, {
    headers: {Accept: "application/json"},
    redirect: "error",
    signal: AbortSignal.timeout(10_000),
  });
  if (!metadataResponse.ok) {
    const status = metadataResponse.status;
    await metadataResponse.body?.cancel();
    throw new Error(`Protected-resource metadata at ${metadataUrl} returned HTTP ${status}.`);
  }
  const raw: unknown = await metadataResponse.json();
  const parsedMetadata = resourceMetadataDocumentSchema.safeParse(raw);
  if (!parsedMetadata.success) throw new Error(`Protected-resource metadata at ${metadataUrl} omitted a valid resource.`);
  const resource = new URL(parsedMetadata.data.resource);
  const resourcePath = resource.pathname;
  const acceptedRootResource = resourcePath === "/api";
  const acceptedTenantResource = /^\/o\/[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?\/api$/u.test(resourcePath);
  if (
    resource.origin !== origin
    || resource.search !== ""
    || resource.hash !== ""
    || (!acceptedRootResource && !acceptedTenantResource)
  ) {
    throw new Error(`Protected-resource metadata at ${metadataUrl} advertised an unexpected resource ${resource.toString()}.`);
  }
  if (apiBasePath.startsWith("/o/") && !apiBasePath.endsWith("/orvex")) {
    const expectedTenantResource = `${apiBasePath}/api`;
    if (resource.pathname !== expectedTenantResource) {
      throw new Error(`Protected-resource metadata at ${metadataUrl} advertised ${resource} for ${apiBasePath}.`);
    }
  }
  return {apiBasePath, metadataUrl, resource};
}

/** Resolve one installation redirect without sending credentials or following it blindly. */
export async function resolveCliApiBasePath(
  address: string,
  initialBasePath = "",
): Promise<string> {
  const origin = new URL(address).origin;
  const response = await probeInstallation(origin, initialBasePath);
  if (response.status !== 308) {
    const status = response.status;
    const url = response.url;
    await response.body?.cancel();
    if (status === 401 || status === 200) return initialBasePath;
    throw new Error(`API base discovery at ${url} returned HTTP ${status}.`);
  }
  const location = response.headers.get("location");
  const url = response.url;
  await response.body?.cancel();
  if (location === null) throw new Error(`API base discovery at ${url} returned HTTP 308 without Location.`);
  const target = new URL(location, origin);
  const match = organizationInstallationPath.exec(target.pathname);
  if (target.origin !== origin || match === null || target.search !== "" || target.hash !== "") {
    throw new Error(`API base discovery at ${url} returned HTTP 308 and refused unsafe redirect to ${target.toString()}.`);
  }
  return `/o/${match[1]}`;
}

async function probeInstallation(origin: string, basePath: string): Promise<Response> {
  const address = `${origin}${basePath}`;
  return fetch(artifactServerRouteUrl(installationRoute, address), {
    headers: {Accept: "application/json"},
    redirect: "manual",
    signal: AbortSignal.timeout(10_000),
  });
}

function resourceMetadataUrl(challenge: string, origin: string, responseUrl: string): URL {
  const parameter = /\bresource_metadata\s*=\s*(?:"((?:[^"\\]|\\.)*)"|([^,\s]+))/iu.exec(challenge);
  const value = parameter?.[1]?.replaceAll(/\\(.)/gu, "$1") ?? parameter?.[2];
  if (value === undefined) {
    throw new Error(`Authentication challenge at ${responseUrl} omitted resource_metadata.`);
  }
  return new URL(value, origin);
}

function isLoopbackHttpUrl(url: URL): boolean {
  return url.protocol === "http:"
    && ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
}
