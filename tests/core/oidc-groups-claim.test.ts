import {Effect} from "effect";
import type {JWTPayload} from "jose";
import {describe, expect, test} from "vitest";

import {readOidcGroupsClaim} from "../../src/identity/oidc-groups-claim.js";

const read = (claims: JWTPayload, claim: string | null) =>
  Effect.runPromise(readOidcGroupsClaim(claims, claim));

describe("readOidcGroupsClaim", () => {
  test("reads the first listed claim the token carries", async () => {
    const claims = {group_paths: ["/Developers"], groups: ["Developers"]};
    expect(await read(claims, "group_paths,groups")).toEqual(["/Developers"]);
  });

  test("falls back to a later listed claim when the first is missing", async () => {
    expect(await read({groups: ["Developers"]}, "group_paths, groups"))
      .toEqual(["Developers"]);
  });

  test("reads null when no listed claim is present", async () => {
    expect(await read({sub: "person"}, "group_paths,groups")).toBeNull();
    expect(await read({groups: []}, null)).toBeNull();
  });

  test("rejects a present claim that is not a list of names", async () => {
    await expect(read({group_paths: "x", groups: []}, "group_paths,groups"))
      .rejects.toThrow("group_paths");
  });
});
