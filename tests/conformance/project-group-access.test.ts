import {createHash} from "node:crypto";
import path from "node:path";
import {DatabaseSync} from "node:sqlite";

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
