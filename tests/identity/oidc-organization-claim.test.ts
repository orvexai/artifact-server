import {describe, expect, test} from "vitest";

import {parseKeycloakOrganizationClaims} from
  "../../src/identity/oidc-organization-claim.js";

const orgId = "1f91f545-13d4-448f-839c-485274165908";

describe("Keycloak Organizations claim", () => {
  test("maps empty groups to viewer and records the identity provider", () => {
    expect(parseKeycloakOrganizationClaims(
      {smoketest: {id: orgId, groups: []}},
      "google",
    )).toEqual({
      ok: true,
      value: {
        identityProvider: "google",
        organizations: [{alias: "smoketest", id: orgId, role: "viewer"}],
      },
    });
  });

  test.each([
    [["/viewer"], "viewer"],
    [["/editor"], "editor"],
    [["/owner"], "owner"],
    [["/viewer", "/editor"], "editor"],
    [["/viewer", "/owner", "/editor"], "owner"],
    [["/unsupported", "/editor"], "editor"],
    [["/unsupported"], null],
  ] as const)("maps %j to %s", (groups, role) => {
    expect(parseKeycloakOrganizationClaims({team: {id: orgId, groups}})).toEqual({
      ok: true,
      value: {
        identityProvider: null,
        organizations: [{alias: "team", id: orgId, role}],
      },
    });
  });

  test("a missing claim grants no organizations", () => {
    expect(parseKeycloakOrganizationClaims(undefined)).toEqual({
      ok: true,
      value: {identityProvider: null, organizations: []},
    });
  });

  test.each([
    [null, "organization must be an alias-keyed object."],
    [[], "organization must be an alias-keyed object."],
    ["smoketest", "organization must be an alias-keyed object."],
    [{smoketest: null}, null],
    [{smoketest: {groups: []}}, null],
    [{smoketest: {id: "not-a-uuid", groups: []}}, null],
    [{smoketest: {id: orgId, groups: [], ignored: true}}, null],
    [{smoketest: {id: orgId, groups: "/owner"}}, null],
    [{smoketest: {id: orgId, groups: ["/owner", 3]}}, null],
  ])("rejects malformed claim %j", (claim, reason) => {
    const expected = reason === null
      ? {
        ok: true,
        value: {identityProvider: null, organizations: []},
      }
      : {ok: false, reason};
    expect(parseKeycloakOrganizationClaims(claim)).toEqual(expected);
  });

  test("skips a malformed sibling while preserving valid memberships", () => {
    expect(parseKeycloakOrganizationClaims({
      bad: {id: "not-a-uuid", groups: []},
      smoketest: {id: orgId, groups: ["/editor"]},
    })).toEqual({
      ok: true,
      value: {
        identityProvider: null,
        organizations: [{alias: "smoketest", id: orgId, role: "editor"}],
      },
    });
  });

  test("rejects a malformed broker claim", () => {
    expect(parseKeycloakOrganizationClaims({}, 42)).toEqual({
      ok: false,
      reason: "identity_provider must be a string when present.",
    });
  });
});
