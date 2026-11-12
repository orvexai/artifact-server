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
    [{smoketest: null}, "organization membership entries must be objects with aliases."],
    [{smoketest: {groups: []}}, "organization smoketest must have a UUID id."],
    [{smoketest: {id: "not-a-uuid", groups: []}}, "organization smoketest must have a UUID id."],
    [{smoketest: {id: orgId, groups: [], ignored: true}}, "organization smoketest has unsupported membership fields."],
    [{smoketest: {id: orgId, groups: "/owner"}}, "organization smoketest groups must be a list of strings."],
    [{smoketest: {id: orgId, groups: ["/owner", 3]}}, "organization smoketest groups must be a list of strings."],
  ])("rejects malformed claim %j", (claim, reason) => {
    expect(parseKeycloakOrganizationClaims(claim)).toEqual({ok: false, reason});
  });

  test("rejects a malformed broker claim", () => {
    expect(parseKeycloakOrganizationClaims({}, 42)).toEqual({
      ok: false,
      reason: "identity_provider must be a string when present.",
    });
  });
});
