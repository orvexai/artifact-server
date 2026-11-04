import {createServer} from "node:http";
import path from "node:path";
import {DatabaseSync} from "node:sqlite";
import {exportJWK, generateKeyPair, SignJWT, type CryptoKey} from "jose";
import {afterEach, beforeEach, describe, expect, test} from "vitest";
import {z} from "zod";

import {OidcMcpBearerVerifier} from "../../src/identity/oidc-mcp-bearer-verifier.js";
import {SqliteIdentityRepository} from "../../src/storage/sqlite-identity-repository.js";
import {createTestInstallation, issueLocalBrowserLogin, removeTestInstallation, startTestServer, type RunningTestServer, type TestInstallation} from "../support/runtime-harness.js";
import {publishNew} from "../support/publishing.js";

const issuerPath = "/realms/artifact";
const audience = "https://staging.artifactserver.test/api";
const serviceSubject = "service-account-houston-v2-subject";

describe("OIDC service account access to artifact responses", () => {
  let installation: TestInstallation;
  let server: RunningTestServer;
  let keyServer: ReturnType<typeof createServer>;
  let issuer: string;
  let privateKey: CryptoKey;
  let keyId: string;
  let artifactId: string;
  let projectId: string;
  let versionId: string;
  let cookie: string;
  let csrf: string;
  let responseId: string;

  beforeEach(async () => {
    const pair = await generateKeyPair("RS256");
    privateKey = pair.privateKey;
    keyId = crypto.randomUUID();
    const publicJwk = {...await exportJWK(pair.publicKey), alg: "RS256", kid: keyId, use: "sig"};
    keyServer = createServer((request, response) => {
      if (request.url === issuerPath + "/protocol/openid-connect/certs") {
        response.setHeader("Content-Type", "application/json");
        response.end(JSON.stringify({keys: [publicJwk]}));
      } else {
        response.statusCode = 404;
        response.end();
      }
    });
    await new Promise<void>((resolve, reject) => {
      keyServer.once("error", reject);
      keyServer.listen(0, "127.0.0.1", resolve);
    });
    const address = z.object({port: z.number().int().positive()}).parse(keyServer.address());
    issuer = "http://127.0.0.1:" + address.port + issuerPath;

    installation = await createTestInstallation();
    server = await startTestServer(installation, {
      apiOAuthResource: {authorizationServers: [issuer], resource: audience},
      externalApiOAuthVerifier: new OidcMcpBearerVerifier({
        audience, groupsClaim: "groups", issuer,
        jwksUri: issuer + "/protocol/openid-connect/certs",
      }),
      groupRolePolicy: {seed: [{role: "viewer", selector: "houston-v2-service"}]},
    });
    const published = await publishNew(server, installation, {
      accessSetting: "account_required", content: "<!doctype html><title>Responses</title>",
      idempotencyKey: "service-account-response", projectId: "prj_default",
    });
    artifactId = published.body.artifact.id;
    projectId = published.body.artifact.projectId;
    versionId = published.body.version.id;
    const loginToken = await issueLocalBrowserLogin(server, installation);
    const login = await fetch(server.baseUrl + "/auth/local?token=" + loginToken, {redirect: "manual"});
    const cookies = login.headers.getSetCookie();
    cookie = cookies.filter((item) => /^artifact_(session|csrf)=/.test(item)).map((item) => item.split(";", 1)[0]).join("; ");
    csrf = cookies.find((item) => item.startsWith("artifact_csrf="))?.split(";", 1)[0]?.split("=", 2)[1] ?? "";
    const create = await memberRequest("POST", "/api/v1/artifacts/" + artifactId + "/responses?projectId=" + projectId, JSON.stringify({questionId: "approval", choice: "yes", versionId}));
    if (create.status !== 201) throw new Error("Could not create the response fixture: " + await create.text());
    responseId = z.object({id: z.string()}).parse(await create.json()).id;

    const databasePath = path.join(installation.dataDirectory, "artifact-server.db");
    const database = new DatabaseSync(databasePath, {readOnly: true});
    let installationId: string;
    try {
      installationId = z.object({installation_id: z.string()}).parse(database.prepare("SELECT installation_id FROM projects WHERE id = ?").get(projectId)).installation_id;
    } finally { database.close(); }
    const repository = new SqliteIdentityRepository(databasePath);
    try {
      await repository.applyDirectoryGroups(installationId, {
        groups: [{id: "grp_houston_v2_service", members: [{email: null, subject: serviceSubject}], name: "houston-v2-service", path: "/houston-v2-service"}],
        provider: "oidc:" + issuer, syncedAt: new Date().toISOString(),
      });
      await repository.setProjectAccessMode(installationId, projectId, "restricted");
      await repository.putProjectGroupGrant(installationId, {
        grantedAt: new Date().toISOString(), grantedByPrincipalId: "test",
        groupId: "grp_houston_v2_service", projectId, role: "viewer",
      });
      if ((await repository.listProjectGroupGrants(installationId, projectId)).length !== 1) {
        throw new Error("The service group project grant was not stored.");
      }
      if (!(await repository.listDirectoryGroups(installationId)).some((group) => group.id === "grp_houston_v2_service")) {
        throw new Error("The service directory group was not stored.");
      }
    } finally { repository.close(); }
  });

  afterEach(async () => {
    await server.stop();
    await new Promise<void>((resolve) => keyServer.close(() => resolve()));
    await removeTestInstallation(installation);
  });

  function memberRequest(method: string, route: string, body?: string): Promise<Response> {
    const headers = new Headers({Cookie: cookie, Origin: server.baseUrl, "Sec-Fetch-Site": "same-origin", "X-CSRF-Token": csrf});
    if (body !== undefined) headers.set("Content-Type", "application/json");
    const init: RequestInit = {headers, method};
    if (body !== undefined) init.body = body;
    return fetch(server.baseUrl + route, init);
  }

  async function serviceToken(): Promise<string> {
    return new SignJWT({
      aud: audience, client_id: "houston-v2", groups: ["houston-v2-service"],
      preferred_username: "service-account-houston-v2",
    }).setProtectedHeader({alg: "RS256", kid: keyId}).setIssuer(issuer)
      .setSubject(serviceSubject).setIssuedAt().setExpirationTime("5m").sign(privateKey);
  }

  test("service account reads shared responses but cannot write", async () => {
    const token = await serviceToken();
    const route = "/api/v1/artifacts/" + artifactId + "/responses";
    const auth = {Authorization: "Bearer " + token};
    const list = await fetch(server.baseUrl + route + "?projectId=" + projectId, {headers: auth});
    expect(list.status).toBe(200);
    expect(list.headers.get("set-cookie")).toBeNull();
    const items = z.object({items: z.array(z.object({authorEmail: z.string().nullable(), id: z.string()}))}).parse(await list.json()).items;
    expect(items.map((item) => item.id)).toContain(responseId);
    expect(items.find((item) => item.id === responseId)?.authorEmail).toBeNull();
    const get = await fetch(server.baseUrl + route + "/" + responseId + "?projectId=" + projectId, {headers: auth});
    expect(get.status).toBe(200);
    expect(get.headers.get("set-cookie")).toBeNull();
    expect((await get.json()).authorEmail).toBeNull();
    const post = await fetch(server.baseUrl + route + "?projectId=" + projectId, {
      body: JSON.stringify({questionId: "second", versionId}),
      headers: {...auth, "Content-Type": "application/json"}, method: "POST",
    });
    expect(post.status).toBe(403);

    const databasePath = path.join(installation.dataDirectory, "artifact-server.db");
    const db = new DatabaseSync(databasePath, {readOnly: true});
    let installationId: string;
    try { installationId = z.object({installation_id: z.string()}).parse(db.prepare("SELECT installation_id FROM projects WHERE id = ?").get(projectId)).installation_id; }
    finally { db.close(); }
    const seedMarkerDb = new DatabaseSync(databasePath);
    try {
      seedMarkerDb.prepare("INSERT INTO directory_group_role_seeds (installation_id, seeded_at) VALUES (?, ?) ON CONFLICT (installation_id) DO NOTHING").run(installationId, new Date().toISOString());
    } finally { seedMarkerDb.close(); }
    const identityRepository = new SqliteIdentityRepository(databasePath);
    try {
      await identityRepository.setGroupRole(installationId, "grp_houston_v2_service", null, new Date().toISOString(), "test");
      expect((await fetch(server.baseUrl + route + "?projectId=" + projectId, {headers: auth})).status).toBe(403);
      await identityRepository.setGroupRole(installationId, "grp_houston_v2_service", "viewer", new Date().toISOString(), "test");
      await identityRepository.removeProjectGroupGrant(installationId, projectId, "grp_houston_v2_service");
    } finally { identityRepository.close(); }
    expect((await fetch(server.baseUrl + route + "?projectId=" + projectId, {headers: auth})).status).toBe(404);
    expect((await fetch(server.baseUrl + route + "/" + responseId + "?projectId=" + projectId, {headers: auth})).status).toBe(404);
  });
});
