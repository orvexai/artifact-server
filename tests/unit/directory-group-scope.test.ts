import {describe, expect, test} from "vitest";

import {
  directoryGroupInScope,
  filterDirectoryGroups,
  type DirectoryGroupScope,
} from "../../src/core/directory-group-scope.js";

describe("directory group scope", () => {
  test("none, roots, Orvex, and all scopes filter full paths", () => {
    const groups = [
      {id: "a", name: "acme", path: "/acme/team"},
      {id: "b", name: "acme-old", path: "/acme-old/team"},
      {id: "guest", name: "Guests", path: "/Guests"},
      {id: "guest-child", name: "Readers", path: "/Guests/Readers"},
      {id: "ordinary", name: "Engineering", path: "/Engineering"},
      {id: "staff", name: "acme-staff", path: "/TenantWorkspaces/acme/acme-staff"},
      {id: "guest-child", name: "acme", path: "/Guests/acme"},
    ];
    const cases: readonly [DirectoryGroupScope, readonly string[]][] = [
      [{kind: "none"}, []],
      [{kind: "roots", roots: ["/acme"]}, ["/acme/team"]],
      [{kind: "roots", roots: []}, []],
      [{kind: "orvex", excludeTenantPaths: false}, groups.map(({path}) => path)],
      [{kind: "orvex", excludeTenantPaths: true}, ["/acme/team", "/acme-old/team", "/Engineering"]],
      [{kind: "orvex", excludeTenantPaths: true, organizationStaffGroups: ["/TenantWorkspaces/{slug}/{slug}-staff"]}, [
        "/acme/team", "/acme-old/team", "/Engineering", "/TenantWorkspaces/acme/acme-staff",
      ]],
      [{kind: "all"}, groups.map(({path}) => path)],
    ];
    for (const [scope, expected] of cases) {
      expect(filterDirectoryGroups(scope, groups).map(({path}) => path)).toEqual(expected);
    }
    expect(directoryGroupInScope({kind: "roots", roots: ["/acme"]}, "/acme-old/team")).toBe(false);
    expect(directoryGroupInScope(
      {kind: "orvex", excludeTenantPaths: true, organizationStaffGroups: ["/TenantWorkspaces/{slug}/{slug}-staff"]},
      "/TenantWorkspaces/acme/acme-old-staff",
    )).toBe(false);
  });
});
