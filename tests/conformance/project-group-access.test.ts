import {createHash} from "node:crypto";
import path from "node:path";
import {DatabaseSync} from "node:sqlite";

import {
  CLIENT_CAPABILITIES_META_KEY,
  CLIENT_INFO_META_KEY,
  PROTOCOL_VERSION_META_KEY,
} from "@modelcontextprotocol/server";
import {afterAll, beforeAll, describe, expect, test} from "vitest";
import {z} from "zod";

import {SqliteIdentityRepository} from "../../src/storage/sqlite-identity-repository.js";
import {ApiClient, signInAdministrator} from "../support/agent-dispatch.js";
import {publishNew} from "../support/publishing.js";
import {
  createTestInstallation,
  removeTestInstallation,
  startTestServer,
  type RunningTestServer,
  type TestInstallation,
} from "../support/runtime-harness.js";

const provider = "oidc:https://idp.example.test/realms/main";
const keyCapabilities = [
  "agent:connect",
  "artifact:manage:any",
  "artifact:read",
  "artifact:create",
  "artifact:publish:any",
  "comment:write",
  "project:manage",
];
const people = ["viewer", "editor", "manager", "outsider"] as const;
type Person = (typeof people)[number];

const projectListSchema = z.object({projects: z.array(z.object({id: z.string()}))});
const toolResultSchema = z.object({
  result: z.object({
    content: z.array(z.object({text: z.string()})),
    isError: z.boolean().optional(),
    structuredContent: z.unknown(),
  }).loose(),
});
const sharingSchema = z.object({
  accessMode: z.string(),
  groups: z.array(z.object({path: z.string(), role: z.string()}).loose()),
  projectId: z.string(),
  yourRole: z.string().nullable(),
});
const listedSchema = z.object({
  projects: z.array(z.object({accessMode: z.string(), id: z.string(), yourRole: z.string().nullable()}).loose()),
});

/** The JSON arguments these tests pass to an MCP tool. */
type ToolArguments = Readonly<Record<
  string,
  string | readonly Readonly<Record<string, string>>[]
>>;

/** The JSON bodies this test posts as the administrator. */
type AdminRequestBody = Readonly<Record<string, string | readonly string[]>>;

function member(person: Person) {
  return {email: `${person}@example.test`, subject: `kc-${person}`};
}

describe("restricted projects shared with directory groups", () => {
  let installation: TestInstallation;
  let server: RunningTestServer;
  let secretProject: string;
  let databasePath: string;
  const keys = new Map<Person, string>();
  /** The outsider's key without project:manage, as an ordinary member's key. */
  let outsiderPlainKey: string;
  const memberIds = new Map<Person, string>();

  beforeAll(async () => {
    installation = await createTestInstallation();
    server = await startTestServer(installation);
    const cookies = await signInAdministrator(server, installation);
    const adminPost = async (url: string, body: AdminRequestBody) => {
      const response = await fetch(`${server.baseUrl}${url}`, {
        body: JSON.stringify(body),
        headers: {
          "Content-Type": "application/json",
          Cookie: cookies.header,
          Origin: server.baseUrl,
          "Sec-Fetch-Mode": "cors",
          "Sec-Fetch-Site": "same-origin",
          "X-CSRF-Token": cookies.csrf,
        },
        method: "POST",
      });
      if (!response.ok) throw new Error(`${url} answered ${response.status}: ${await response.text()}`);
      return response.json();
    };

    const created = await fetch(`${server.baseUrl}/api/v1/projects`, {
      body: JSON.stringify({name: "Secret"}),
      headers: {
        Authorization: `Bearer ${installation.apiToken}`,
        "Content-Type": "application/json",
        "Idempotency-Key": "create-secret-project",
      },
      method: "POST",
    });
    secretProject = z.object({project: z.object({id: z.string()})})
      .parse(await created.json()).project.id;

    for (const person of people) {
      // Sequential: each admission and key issue is its own audited write.
      // oxlint-disable-next-line eslint/no-await-in-loop
      const admitted = z.object({member: z.object({id: z.string()})}).parse(await adminPost(
        "/api/v1/members",
        {displayName: person, email: `${person}@example.test`, role: "member"},
      ));
      memberIds.set(person, admitted.member.id);
      // oxlint-disable-next-line eslint/no-await-in-loop
      const issued = z.object({token: z.string()}).parse(await adminPost("/api/v1/api-keys", {
        capabilities: keyCapabilities,
        expiresAt: "2099-01-01T00:00:00.000Z",
        memberId: admitted.member.id,
        name: `${person} key`,
      }));
      keys.set(person, issued.token);
    }
    const outsiderId = memberIds.get("outsider");
    if (outsiderId === undefined) throw new Error("The outsider was not admitted.");
    outsiderPlainKey = z.object({token: z.string()}).parse(await adminPost("/api/v1/api-keys", {
      capabilities: keyCapabilities.filter((capability) => capability !== "project:manage"),
      expiresAt: "2099-01-01T00:00:00.000Z",
      memberId: outsiderId,
      name: "outsider plain key",
    })).token;

    // Copy three groups as directory sync would, then restrict and share.
    databasePath = path.join(installation.dataDirectory, "artifact-server.db");
    const installationId = z.object({installation_id: z.string()}).parse(
      new DatabaseSync(databasePath, {readOnly: true})
        .prepare("SELECT installation_id FROM projects WHERE id = ?").get(secretProject),
    ).installation_id;
    const repository = new SqliteIdentityRepository(databasePath);
    try {
      await repository.applyDirectoryGroups(installationId, {
        groups: [
          {id: "g-view", members: [member("viewer")], name: "Viewers", path: "/Viewers"},
          {id: "g-edit", members: [member("editor")], name: "Editors", path: "/Editors"},
          {id: "g-manage", members: [member("manager")], name: "Managers", path: "/Managers"},
        ],
        provider,
        syncedAt: "2026-10-24T00:00:00.000Z",
      });
      await repository.setProjectAccessMode(installationId, secretProject, "restricted");
      await Promise.all(([
        ["g-view", "viewer"],
        ["g-edit", "editor"],
        ["g-manage", "manager"],
      ] as const).map(([groupId, role]) => repository.putProjectGroupGrant(installationId, {
        grantedAt: "2026-10-24T00:00:00.000Z",
        grantedByPrincipalId: "test",
        groupId,
        projectId: secretProject,
        role,
      })));
    } finally {
      repository.close();
    }
  });

  afterAll(async () => {
    await server.stop();
    await removeTestInstallation(installation);
  });

  test("only granted members and service keys see a restricted project", async () => {
    const listed = async (token: string) =>
      projectListSchema.parse(await (await get("/api/v1/projects", token)).json())
        .projects.map((project) => project.id);
    expect(await listed(key("outsider"))).not.toContain(secretProject);
    expect(await listed(key("outsider"))).toContain("prj_default");
    const granted = await Promise.all(
      (["viewer", "editor", "manager"] as const).map((person) => listed(key(person))),
    );
    for (const projects of granted) expect(projects).toContain(secretProject);
    expect(await listed(installation.apiToken)).toContain(secretProject);

    expect((await get(`/api/v1/projects/${secretProject}`, key("outsider"))).status).toBe(404);
    expect((await get(`/api/v1/projects/${secretProject}`, key("viewer"))).status).toBe(200);
  });

  test("publishing needs an editor; an outsider is told the project does not exist", async () => {
    expect((await createUpload(key("viewer"), secretProject)).status).toBe(403);
    expect((await createUpload(key("outsider"), secretProject)).status).toBe(404);
    expect((await createUpload(key("editor"), secretProject)).ok).toBe(true);
    expect((await createUpload(key("manager"), secretProject)).ok).toBe(true);
    expect((await createUpload(installation.apiToken, secretProject)).ok).toBe(true);
  });

  test("renaming needs a manager", async () => {
    expect((await rename(key("viewer"), "Viewer rename")).status).toBe(403);
    expect((await rename(key("editor"), "Editor rename")).status).toBe(403);
    // The outsider cannot see the project, so it is not told it exists.
    expect((await rename(key("outsider"), "Outsider rename")).status).toBe(404);
    expect((await rename(key("manager"), "Managed")).status).toBe(200);
  });

  test("project threads go only to agents whose owner can see the project", async () => {
    const published = (await publishNew(server, installation, {
      accessSetting: "account_required",
      content: "<!doctype html><title>Secret page</title>",
      idempotencyKey: "publish-secret-page",
      projectId: secretProject,
    })).body;
    const viewer = new ApiClient(server, key("viewer"));
    const thread = await viewer.openThread(published, "Please look", "group-access-viewer-thread");
    // Only service keys register agents; a member's agent is its MCP
    // mailbox. Register with the service key, then hand each one to an owner.
    const service = new ApiClient(server, installation.apiToken);
    const register = (connectionKey: string) => service.registerAgent({
      connectionKey,
      displayName: connectionKey,
      workingDirectory: `/tmp/${connectionKey}`,
    });
    const [outsiderAgent, viewerAgent, serviceAgent] = await Promise.all(
      ["outsider-agent", "viewer-agent", "service-agent"].map(register),
    );
    if (outsiderAgent === undefined || viewerAgent === undefined || serviceAgent === undefined) {
      throw new Error("Agent registration returned too few agents.");
    }
    const owners = new DatabaseSync(databasePath);
    try {
      const own = owners.prepare("UPDATE registered_agents SET principal_id = ? WHERE id = ?");
      own.run(memberId("outsider"), outsiderAgent.id);
      own.run(memberId("viewer"), viewerAgent.id);
    } finally {
      owners.close();
    }
    const toOutsider = await viewer.sendDispatch({
      agentId: outsiderAgent.id,
      idempotencyKey: "group-access-dispatch-to-outsider",
      projectId: secretProject,
      threadIds: [thread.id],
    });
    expect(toOutsider.status).toBe(403);
    expect(await toOutsider.text()).toContain("cannot see this project");
    const toOwnAgent = await viewer.sendDispatch({
      agentId: viewerAgent.id,
      idempotencyKey: "group-access-dispatch-to-viewer-agent",
      projectId: secretProject,
      threadIds: [thread.id],
    });
    expect(toOwnAgent.ok, `toOwnAgent: ${toOwnAgent.status} ${await toOwnAgent.clone().text()}`).toBe(true);
    const secondThread = await viewer.openThread(published, "Also this", "group-access-viewer-thread-2");
    const toServiceAgent = await viewer.sendDispatch({
      agentId: serviceAgent.id,
      idempotencyKey: "group-access-dispatch-to-service-agent",
      projectId: secretProject,
      threadIds: [secondThread.id],
    });
    expect(toServiceAgent.ok, `toServiceAgent: ${toServiceAgent.status} ${await toServiceAgent.clone().text()}`).toBe(true);

    // Clearing removes other people's threads, so a viewer may not.
    const clear = (person: Person) => new ApiClient(server, key(person)).fetch(
      `/api/v1/projects/${secretProject}/artifacts/${published.artifact.id}/comments/clear`,
      {body: JSON.stringify({state: "resolved"}), method: "POST"},
    );
    expect((await clear("viewer")).status).toBe(403);
    const editorClear = await clear("editor");
    expect(editorClear.ok, `editor clear: ${editorClear.status} ${await editorClear.clone().text()}`).toBe(true);
  });

  test("an installation project keeps today's rules for everyone", async () => {
    expect((await createUpload(key("outsider"), "prj_default")).ok).toBe(true);
    expect((await get("/api/v1/projects/prj_default", key("outsider"))).status).toBe(200);
  });

  function memberId(person: Person): string {
    const id = memberIds.get(person);
    if (id === undefined) throw new Error(`No member for ${person}.`);
    return id;
  }

  test("an agent creates a restricted project, shares it, and controls who can see it", async () => {
    const created = await tool(key("editor"), "project_create", {
      name: "Agent project",
      shareWith: [{group: "/Viewers", role: "viewer"}],
    });
    expect(created.isError).not.toBe(true);
    const sharing = sharingSchema.parse(
      z.object({sharing: z.unknown()}).parse(created.structuredContent).sharing,
    );
    expect(sharing).toMatchObject({
      accessMode: "restricted",
      groups: [{path: "/Viewers", role: "viewer"}],
      yourRole: "manager",
    });
    const projectId = sharing.projectId;

    const visibleTo = async (person: Person) =>
      listedSchema.parse((await tool(key(person), "project_list", {})).structuredContent)
        .projects.find((project) => project.id === projectId);
    expect(await visibleTo("outsider")).toBeUndefined();
    expect(await visibleTo("viewer")).toMatchObject({accessMode: "restricted", yourRole: "viewer"});

    const viewerShare = await tool(key("viewer"), "project_share", {
      group: "Managers",
      projectId,
      role: "editor",
    });
    expect(viewerShare.isError).toBe(true);
    expect(viewerShare.content[0]?.text).toContain("AUTHORIZATION_DENIED");

    const unknown = await tool(key("editor"), "project_share", {
      group: "No Such Group",
      projectId,
      role: "viewer",
    });
    expect(unknown.isError).toBe(true);
    expect(unknown.content[0]?.text).toContain("GROUP_NOT_FOUND");

    const shared = await tool(key("editor"), "project_share", {
      group: "Managers",
      projectId,
      role: "editor",
    });
    expect(sharingSchema.parse(z.object({sharing: z.unknown()}).parse(shared.structuredContent).sharing)
      .groups.map(({path: groupPath, role}) => `${groupPath}:${role}`).toSorted())
      .toEqual(["/Managers:editor", "/Viewers:viewer"]);
    expect(await visibleTo("manager")).toMatchObject({yourRole: "editor"});

    await tool(key("editor"), "project_unshare", {group: "/Viewers", projectId});
    expect(await visibleTo("viewer")).toBeUndefined();

    const opened = await tool(key("editor"), "project_set_access", {
      accessMode: "installation",
      projectId,
    });
    expect(opened.isError).not.toBe(true);
    expect(await visibleTo("outsider")).toMatchObject({accessMode: "installation", yourRole: null});

    // The creator can restrict it again; another member of an open project cannot.
    const outsiderRestrict = await tool(outsiderPlainKey, "project_set_access", {
      accessMode: "restricted",
      projectId,
    });
    expect(outsiderRestrict.isError).toBe(true);
    const restricted = await tool(key("editor"), "project_set_access", {
      accessMode: "restricted",
      projectId,
    });
    expect(restricted.isError).not.toBe(true);
    expect(await visibleTo("outsider")).toBeUndefined();

    // Viewers see which groups it is shared with, not who shared it.
    const sharingAsManager = await tool(key("manager"), "project_sharing", {projectId});
    expect(JSON.stringify(sharingAsManager.structuredContent)).not.toContain("grantedByPrincipalId");
  });

  async function tool(token: string, name: string, args: ToolArguments) {
    const response = await fetch(`${server.baseUrl}/mcp`, {
      body: JSON.stringify({
        id: crypto.randomUUID(),
        jsonrpc: "2.0",
        method: "tools/call",
        params: {
          _meta: {
            [CLIENT_CAPABILITIES_META_KEY]: {},
            [CLIENT_INFO_META_KEY]: {name: "group-access-test", version: "1"},
            [PROTOCOL_VERSION_META_KEY]: "2026-07-28",
          },
          arguments: args,
          name,
        },
      }),
      headers: {
        Accept: "application/json, text/event-stream",
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
        "MCP-Protocol-Version": "2026-07-28",
        "Mcp-Method": "tools/call",
        "Mcp-Name": name,
      },
      method: "POST",
    });
    expect(response.status).toBe(200);
    return toolResultSchema.parse(await response.json()).result;
  }

  function key(person: Person): string {
    const token = keys.get(person);
    if (token === undefined) throw new Error(`No key for ${person}.`);
    return token;
  }

  function get(url: string, token: string): Promise<Response> {
    return fetch(`${server.baseUrl}${url}`, {headers: {Authorization: `Bearer ${token}`}});
  }

  function rename(token: string, name: string): Promise<Response> {
    return fetch(`${server.baseUrl}/api/v1/projects/${secretProject}`, {
      body: JSON.stringify({name}),
      headers: {Authorization: `Bearer ${token}`, "Content-Type": "application/json"},
      method: "PATCH",
    });
  }

  function createUpload(token: string, projectId: string): Promise<Response> {
    const bytes = Buffer.from("<!doctype html><title>x</title>");
    return fetch(`${server.baseUrl}/api/v1/uploads`, {
      body: JSON.stringify({
        entryPath: "index.html",
        files: [{
          mediaType: "text/html",
          path: "index.html",
          sha256: createHash("sha256").update(bytes).digest("hex"),
          size: bytes.byteLength,
        }],
        projectId,
        routingMode: "static",
      }),
      headers: {Authorization: `Bearer ${token}`, "Content-Type": "application/json"},
      method: "POST",
    });
  }
});
