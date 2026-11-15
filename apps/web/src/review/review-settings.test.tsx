import {createElement} from "react";
import {renderToStaticMarkup} from "react-dom/server";
import {afterEach, describe, expect, test, vi} from "vitest";

import type {Session} from "@/api/client";
import {ReviewSettings} from "./review-settings.tsx";

describe("tenant settings navigation", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
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
});
