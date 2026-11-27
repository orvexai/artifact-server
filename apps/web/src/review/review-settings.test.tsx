import {createElement} from "react";
import {renderToStaticMarkup} from "react-dom/server";
import {afterEach, describe, expect, test, vi} from "vitest";

import type {Session} from "@/api/client";
import {ReviewSettings, settingsLandingDestination, visibleSettingsPages} from "./review-settings.tsx";

const pages = (role: "administrator" | "member" | "owner" | "viewer") => visibleSettingsPages({
  canManageProjects: true,
  directoryGroups: true,
  directHuman: true,
  organizationKind: "tenant",
  role,
});

describe("tenant settings navigation", () => {
  test.each([
    ["viewer", "tenant", ["mcp"]],
    ["member", "tenant", ["mcp", "projects"]],
    ["owner", "tenant", ["apiKeys", "members", "mcp", "projects", "publicLinks", "webmcp"]],
    ["administrator", "tenant", ["apiKeys", "members", "mcp", "projects", "publicLinks", "webmcp"]],
    ["viewer", "installation", ["mcp", "projects", "webmcp"]],
    ["member", "installation", ["groups", "mcp", "projects", "webmcp"]],
    ["owner", "installation", ["apiKeys", "groups", "members", "mcp", "projects", "publicLinks", "webmcp"]],
    ["administrator", "installation", ["apiKeys", "groups", "members", "mcp", "projects", "publicLinks", "webmcp"]],
  ] as const)("role %s in %s sees exactly its settings pages", (role, organizationKind, expected) => {
    const actual = visibleSettingsPages({canManageProjects: true, directoryGroups: true, directHuman: true, organizationKind, role});
    expect([...actual].toSorted()).toEqual([...expected].toSorted());
  });

  test.each([
    ["viewer", "/o/acme/review/settings/mcp"],
    ["member", "/o/acme/review/settings/projects"],
    ["owner", "/o/acme/review/settings/projects"],
    ["administrator", "/o/acme/review/settings/projects"],
  ] as const)("redirects the %s settings landing to its first visible page", (role, expected) => {
    vi.stubGlobal("document", {querySelector: () => ({content: "/o/acme"})});
    expect(settingsLandingDestination(pages(role))).toBe(expected);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  test("renders a not-available state for a direct URL to a hidden tenant page", () => {
    vi.stubGlobal("document", {querySelector: () => ({content: "/o/acme"})});
    vi.stubGlobal("window", {
      location: {origin: "https://artifact.example.test", pathname: "/o/acme/review/settings/groups"},
      sessionStorage: {getItem: () => null},
    });
    const session = {
      authenticationMethod: "session",
      capabilities: {directoryGroups: true, gitHistory: {limits: {fileCopyBytes: 0, logicalCopiedBytes: 0, logicalReservedBytes: 0, storageBudgetBytes: null, versionCopyBytes: 0}, provider: null, providerState: "disabled"}, linkedArtifacts: false},
      principal: {authorizedByPrincipalId: null, capabilities: [], displayName: "Acme viewer", id: "viewer", installationId: "installation-acme", kind: "human", membershipRole: "viewer"},
    } satisfies Session;
    const html = renderToStaticMarkup(createElement(ReviewSettings, {
      onProjectsChanged: async () => [], onThemeChange: () => undefined, projects: [], session, theme: "moon",
    }));
    expect(html).toContain("Settings page not available");
    expect(html).not.toContain("Page not found");
    expect(html).not.toContain("Sign in");
  });

  test("tenant project settings follow the server per-project management flag", () => {
    vi.stubGlobal("document", {querySelector: () => ({content: "/o/acme"})});
    vi.stubGlobal("window", {
      location: {origin: "https://artifact.example.test", pathname: "/o/acme/review/settings/projects/project-1"},
      sessionStorage: {getItem: () => null},
    });
    const session = {
      authenticationMethod: "session",
      capabilities: {directoryGroups: true, gitHistory: {limits: {fileCopyBytes: 0, logicalCopiedBytes: 0, logicalReservedBytes: 0, storageBudgetBytes: null, versionCopyBytes: 0}, provider: null, providerState: "disabled"}, linkedArtifacts: false},
      principal: {authorizedByPrincipalId: null, capabilities: [], displayName: "Acme member", id: "member", installationId: "installation-acme", kind: "human", membershipRole: "member"},
    } satisfies Session;
    const render = (canManage: boolean) => renderToStaticMarkup(createElement(ReviewSettings, {
      onProjectsChanged: async () => [], onThemeChange: () => undefined,
      projects: [{archivedAt: null, canManage, createdAt: "2026-01-01T00:00:00.000Z", id: "project-1", installationId: "installation-acme", name: "Project one"}],
      session, theme: "moon",
    }));

    expect(render(false)).toContain("Project permission required");
    expect(render(true)).not.toContain("Project permission required");
  });

  test.each(["/o/acme", "/o/orvex"])("renders every in-app link below %s", (basePath) => {
    vi.stubGlobal("document", {
      querySelector: () => ({content: basePath}),
    });
    vi.stubGlobal("window", {
      location: {
        origin: "https://artifact.example.test",
        pathname: `${basePath}/review/settings/mcp`,
      },
      sessionStorage: {getItem: () => null},
    });

    const session = {
      authenticationMethod: "session",
      capabilities: {
        directoryGroups: true,
        gitHistory: {
          limits: {
            fileCopyBytes: 0,
            logicalCopiedBytes: 0,
            logicalReservedBytes: 0,
            storageBudgetBytes: null,
            versionCopyBytes: 0,
          },
          provider: null,
          providerState: "disabled",
        },
        linkedArtifacts: false,
      },
      principal: {
        authorizedByPrincipalId: null,
        capabilities: ["project:manage"],
        displayName: "Acme owner",
        id: "principal-acme",
        installationId: "installation-acme",
        kind: "human",
        membershipRole: "owner",
      },
    } satisfies Session;

    const html = renderToStaticMarkup(createElement(ReviewSettings, {
      onProjectsChanged: async () => [],
      onThemeChange: () => undefined,
      projects: [],
      session,
      theme: "moon",
    }));
    const hrefs = [...html.matchAll(/\shref="([^"]+)"/gu)].map(([, href]) => href);

    expect(hrefs.length).toBeGreaterThan(0);
    expect(hrefs.every((href) => href?.startsWith(`${basePath}/`))).toBe(true);
  });

  test("hides the Groups link and route when directory groups are unavailable", () => {
    vi.stubGlobal("document", {querySelector: () => ({content: "/o/acme"})});
    vi.stubGlobal("window", {
      location: {origin: "https://artifact.example.test", pathname: "/o/acme/review/settings/groups"},
      sessionStorage: {getItem: () => null},
    });
    const session = {
      authenticationMethod: "session",
      capabilities: {directoryGroups: false, gitHistory: {limits: {fileCopyBytes: 0, logicalCopiedBytes: 0, logicalReservedBytes: 0, storageBudgetBytes: null, versionCopyBytes: 0}, provider: null, providerState: "disabled"}, linkedArtifacts: false},
      principal: {authorizedByPrincipalId: null, capabilities: [], displayName: "Acme member", id: "member", installationId: "installation-acme", kind: "human", membershipRole: "member"},
    } satisfies Session;
    const html = renderToStaticMarkup(createElement(ReviewSettings, {
      onProjectsChanged: async () => [], onThemeChange: () => undefined, projects: [], session, theme: "moon",
    }));

    expect(html).not.toContain("href=\"/o/acme/review/settings/groups\"");
    expect(html).toContain("Page not found");
  });
});
