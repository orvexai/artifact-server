import {describe, expect, it, vi} from "vitest";

import {listArtifactComments} from "../../src/cli/comments-command.js";

describe("listArtifactComments", () => {
  it("reads every comment page using the CLI's authenticated server connection", async () => {
    const fetchImpl = vi.fn<typeof fetch>(async (input, init) => {
      const url = new URL(input instanceof Request ? input.url : input.toString());
      expect(url.pathname).toBe("/api/v1/artifacts/artifact%2Fone/comments");
      expect(url.searchParams.get("projectId")).toBe("project-1");
      expect(url.searchParams.get("versionId")).toBe("version-2");
      expect(url.searchParams.get("dispatched")).toBe("include");
      expect(init?.headers).toEqual({
        Authorization: "Bearer cli-managed-credential",
        Accept: "application/json",
      });
      expect(init?.redirect).toBe("error");
      const cursor = url.searchParams.get("cursor");
      return new Response(JSON.stringify(cursor === null
        ? {
          items: [thread("comment-1"), thread("comment-2")],
          nextCursor: "next page",
        }
        : {items: [thread("comment-3")], nextCursor: null}), {
        status: 200,
        headers: {"Content-Type": "application/json"},
      });
    });

    const items = await listArtifactComments({
      artifactId: "artifact/one",
      apiToken: "cli-managed-credential",
      dispatched: "include",
      fetchImpl,
      limit: 3,
      origin: "https://artifacts.example.test",
      projectId: "project-1",
      versionId: "version-2",
    });

    expect(items.map((item) => item.id)).toEqual([
      "comment-1",
      "comment-2",
      "comment-3",
    ]);
    expect(fetchImpl).toHaveBeenCalledTimes(2);
  });

  it("rejects an invalid requested limit before making a request", async () => {
    const fetchImpl = vi.fn<typeof fetch>();
    await expect(listArtifactComments({
      artifactId: "artifact-1",
      apiToken: "cli-managed-credential",
      dispatched: "exclude",
      fetchImpl,
      limit: 0,
      origin: "https://artifacts.example.test",
    })).rejects.toThrow("Comment limit must be a whole number from 1 to 5000.");
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it("can include reply bodies with each thread", async () => {
    const fetchImpl = vi.fn<typeof fetch>(async (input) => {
      const url = new URL(input instanceof Request ? input.url : input.toString());
      if (url.pathname.endsWith("/comments")) {
        return new Response(JSON.stringify({items: [thread("comment-1")], nextCursor: null}));
      }
      return new Response(JSON.stringify({
        replies: [{
          author: {
            authorizedByPrincipalId: null,
            displayName: "MCP client artifact-server for Reviewer",
            principalId: "human-reviewer-1",
            principalKind: "human",
          },
          body: "Please clarify this step.",
          createdAt: "2026-10-13T00:01:00.000Z",
          id: "reply-1",
          threadId: "comment-1",
          updatedAt: "2026-10-13T00:01:00.000Z",
        }],
        thread: thread("comment-1"),
      }));
    });

    const items = await listArtifactComments({
      artifactId: "artifact-1",
      apiToken: "cli-managed-credential",
      dispatched: "include",
      fetchImpl,
      includeReplies: true,
      limit: 10,
      origin: "https://artifacts.example.test",
    });

    expect(items[0]?.replies?.map((reply) => reply.body)).toEqual([
      "Please clarify this step.",
    ]);
    expect(items[0]?.author).toEqual({
      authorizedByPrincipalId: null,
      displayName: "MCP client artifact-server for Reviewer",
      principalId: "human-reviewer-1",
      principalKind: "human",
    });
    expect(items[0]?.replies?.[0]?.author).toEqual({
      authorizedByPrincipalId: null,
      displayName: "MCP client artifact-server for Reviewer",
      principalId: "human-reviewer-1",
      principalKind: "human",
    });
    expect(fetchImpl).toHaveBeenCalledTimes(2);
  });
});

function thread(id: string) {
  return {
    artifactId: "artifact/one",
    author: {
      authorizedByPrincipalId: null,
      displayName: "MCP client artifact-server for Reviewer",
      principalId: "human-reviewer-1",
      principalKind: "human",
    },
    body: `Feedback ${id}`,
    createdAt: "2026-10-13T00:00:00.000Z",
    id,
    path: null,
    projectId: "project-1",
    replyCount: 0,
    state: "open",
    updatedAt: "2026-10-13T00:00:00.000Z",
    versionId: "version-2",
  };
}
