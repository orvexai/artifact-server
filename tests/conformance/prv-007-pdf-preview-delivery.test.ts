import {mkdtemp, rm, writeFile} from "node:fs/promises";
import {tmpdir} from "node:os";
import path from "node:path";

import {afterEach, beforeEach, describe, expect, test} from "vitest";
import {z} from "zod";

import {multiPagePdf} from "../support/pdf-fixture.js";
import {
  commitStagedUpload,
  createStagedUpload,
  type PublishResponse,
  type TestSiteFile,
  uploadEveryStagedFile,
} from "../support/publishing.js";
import {
  createTestInstallation,
  fetchVersion,
  removeTestInstallation,
  type RunningTestServer,
  startTestServer,
  type TestInstallation,
} from "../support/runtime-harness.js";

const failureSchema = z.object({
  error: z.object({code: z.string(), message: z.string()}).strict(),
}).strict();
const previewLeaseSchema = z.object({
  baseUrl: z.url(),
  expiresAt: z.string(),
  versionId: z.string(),
});

const pdfBytes = multiPagePdf([
  ["Quarterly report", "Page one"],
  ["Appendix", "Page two"],
]);
const pdfFiles: readonly TestSiteFile[] = [
  {bytes: pdfBytes, mediaType: "application/pdf", path: "reports/q3 report.pdf"},
  {
    bytes: new TextEncoder().encode("<!doctype html><title>Index</title>"),
    mediaType: "text/html; charset=utf-8",
    path: "index.html",
  },
];

/** The policy every directive but `frame-src` carried before PDF previews. */
function applicationShellPolicy(contentDomain: string): string {
  return [
    "default-src 'self'",
    "base-uri 'none'",
    "connect-src 'self'",
    "font-src 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
    `frame-src 'self' http://*.${contentDomain}:* https://*.${contentDomain}`,
    "img-src 'self' data:",
    "object-src 'none'",
    "script-src 'self'",
    "style-src 'self'",
  ].join("; ");
}

describe("PRV-007 PDF preview delivery", () => {
  let installation: TestInstallation;
  let server: RunningTestServer;
  let webAssetsRoot: string;

  beforeEach(async () => {
    installation = await createTestInstallation();
    webAssetsRoot = await mkdtemp(path.join(tmpdir(), "artifact-server-pdf-assets-"));
    await writeFile(path.join(webAssetsRoot, "review.html"), "<!doctype html><title>Review</title>");
    await writeFile(path.join(webAssetsRoot, "review-frame.html"), "<!doctype html><title>Frame</title>");
    server = await startTestServer(installation, {webAssetsRoot});
  });

  afterEach(async () => {
    await server.stop();
    await removeTestInstallation(installation);
    await rm(webAssetsRoot, {force: true, recursive: true});
  });

  test("PRV-007: the application shell may frame only itself and the exact-version content hosts", async () => {
    const shells = await Promise.all(
      ["/review", "/review/settings/projects"].map((route) =>
        fetch(`${server.baseUrl}${route}`)
      ),
    );
    for (const shell of shells) {
      expect(shell.status).toBe(200);
      expect(shell.headers.get("content-security-policy"))
        .toBe(applicationShellPolicy("localhost"));
      expect(shell.headers.get("x-frame-options")).toBeNull();
    }

    // The isolated review frame keeps its own policy: it frames nothing.
    const frame = await fetch(`${server.baseUrl}/review-frame`);
    expect(frame.status).toBe(200);
    expect(frame.headers.get("content-security-policy")).toBe([
      "default-src 'none'",
      "script-src 'self' 'unsafe-inline' http://*.localhost:* https://*.localhost",
      "style-src 'self' 'unsafe-inline' http://*.localhost:* https://*.localhost",
      "img-src 'self' * data: blob:",
      "font-src * data:",
      "media-src * data: blob:",
      "connect-src http://*.localhost:* https://*.localhost",
      "frame-ancestors 'self'",
    ].join("; "));

    // The frame sources follow the configured content domain, not a wildcard.
    await server.stop();
    server = await startTestServer(installation, {
      contentDomain: "content.example.test",
      webAssetsRoot,
    });
    const hosted = await fetch(`${server.baseUrl}/review`);
    expect(hosted.headers.get("content-security-policy"))
      .toBe(applicationShellPolicy("content.example.test"));
  });

  test("PRV-007: a preview lease serves a PDF entry inline to a cookie-less framed navigation on its content host", async () => {
    const published = await publishPdfFixture(server, installation);
    const lease = await issuePreviewLease(server, installation, published);
    const leaseHost = new URL(lease.baseUrl);
    expect(leaseHost.hostname).toMatch(/^review-[a-z0-9]+\.localhost$/u);
    expect(leaseHost.origin).not.toBe(new URL(server.baseUrl).origin);

    const pdfUrl = new URL("reports/q3%20report.pdf", lease.baseUrl).toString();
    const framed = await fetchVersion(server, pdfUrl, "GET", frameNavigationHeaders());
    expect(framed.status).toBe(200);
    expect(framed.headers.get("content-type")).toBe("application/pdf");
    expect(framed.headers.get("content-disposition")).toBe("inline");
    expect(framed.headers.get("x-content-type-options")).toBe("nosniff");
    expect(framed.headers.get("cache-control")).toBe("private, no-store");
    expect(framed.headers.get("referrer-policy")).toBe("no-referrer");
    // Nothing on the response stops the application origin from framing it.
    expect(framed.headers.get("x-frame-options")).toBeNull();
    expect(framed.headers.get("content-security-policy")).toBeNull();
    expect(framed.headers.get("set-cookie")).toBeNull();
    expect(new Uint8Array(await framed.arrayBuffer())).toEqual(pdfBytes);

    // Browser PDF viewers read large documents by range.
    const ranged = await fetchVersion(server, pdfUrl, "GET", {
      ...frameNavigationHeaders(),
      Range: "bytes=0-7",
    });
    expect(ranged.status).toBe(206);
    expect(ranged.headers.get("content-range")).toBe(`bytes 0-7/${pdfBytes.byteLength}`);
    expect(new TextDecoder().decode(await ranged.arrayBuffer())).toBe("%PDF-1.4");
    const head = await fetchVersion(server, pdfUrl, "HEAD", frameNavigationHeaders());
    expect(head.status).toBe(200);
    expect(head.headers.get("content-length")).toBe(String(pdfBytes.byteLength));

    // The lease is the only authority: a forged lease is refused, and the
    // private version's ordinary content host still needs a content session.
    const forged = new URL(pdfUrl);
    forged.hostname = `review-${"0".repeat(56)}.localhost`;
    expect((await fetchVersion(server, forged.toString(), "GET", frameNavigationHeaders())).status)
      .toBe(401);
    expect((await fetchVersion(
      server,
      new URL("reports/q3%20report.pdf", published.links.version).toString(),
      "GET",
      frameNavigationHeaders(),
    )).status).toBe(401);
  });

  test("PRV-007: a PDF is never served as a document from the application origin", async () => {
    const published = await publishPdfFixture(server, installation);
    const sessionCookie = await createLocalOwnerSession(server);
    const query = new URLSearchParams({
      path: "reports/q3 report.pdf",
      projectId: published.artifact.projectId,
    });
    const versionRoute = `${server.baseUrl}/api/v1/artifacts/${published.artifact.id}/versions/${published.version.id}`;

    const refusals = await Promise.all(
      ["iframe", "document", "embed", "object"].map(async (destination) => {
        const media = await fetchVersion(server, `${versionRoute}/media?${query}`, "GET", {
          Cookie: sessionCookie,
          "Sec-Fetch-Dest": destination,
          "Sec-Fetch-Mode": destination === "iframe" || destination === "document"
            ? "navigate"
            : "no-cors",
          "Sec-Fetch-Site": "same-origin",
        });
        return {
          code: failureSchema.parse(await media.json()).error.code,
          status: media.status,
        };
      }),
    );
    expect(refusals).toEqual(Array.from({length: 4}, () => ({
      code: "MEDIA_PREVIEW_TYPE_UNSUPPORTED",
      status: 415,
    })));

    const download = await fetchVersion(server, `${versionRoute}/file?${query}`, "GET", {
      Authorization: `Bearer ${installation.apiToken}`,
    });
    expect(download.status).toBe(200);
    expect(download.headers.get("content-type")).toBe("application/octet-stream");
    expect(download.headers.get("content-disposition")).toMatch(/^attachment;/u);
    expect(download.headers.get("x-content-type-options")).toBe("nosniff");
  });
});

/** What a browser sends when an application page frames a content host. */
function frameNavigationHeaders() {
  return {
    "Sec-Fetch-Dest": "iframe",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "cross-site",
  } as const;
}

async function publishPdfFixture(
  server: RunningTestServer,
  installation: TestInstallation,
): Promise<PublishResponse> {
  const upload = await createStagedUpload(
    server,
    installation,
    "reports/q3 report.pdf",
    pdfFiles,
  );
  await uploadEveryStagedFile(installation, upload.body, pdfFiles);
  return (await commitStagedUpload(installation, upload.body, "prv-007-pdf-delivery", {
    accessSetting: "account_required",
    kind: "new_artifact",
    name: "PDF report",
    tags: [],
  })).body;
}

async function issuePreviewLease(
  server: RunningTestServer,
  installation: TestInstallation,
  published: PublishResponse,
): Promise<z.infer<typeof previewLeaseSchema>> {
  const response = await fetch(
    `${server.baseUrl}/api/v1/artifacts/${published.artifact.id}/versions/${published.version.id}/preview-leases?projectId=${published.artifact.projectId}`,
    {headers: {Authorization: `Bearer ${installation.apiToken}`}, method: "POST"},
  );
  expect(response.status).toBe(201);
  const lease = previewLeaseSchema.parse(await response.json());
  expect(lease.versionId).toBe(published.version.id);
  return lease;
}

async function createLocalOwnerSession(server: RunningTestServer): Promise<string> {
  const response = await fetch(`${server.baseUrl}/auth/local-owner`, {
    headers: {
      Origin: server.baseUrl,
      "Sec-Fetch-Mode": "cors",
      "Sec-Fetch-Site": "same-origin",
    },
    method: "POST",
  });
  if (response.status !== 204) {
    throw new Error("The test server did not issue a local-owner session.");
  }
  const pair = response.headers.getSetCookie()
    .find((value) => value.startsWith("artifact_session="))
    ?.split(";", 1)[0];
  if (pair === undefined) {
    throw new Error("The local-owner response omitted its session cookie.");
  }
  return pair;
}
