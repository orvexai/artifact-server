import {describe, expect, test} from "vitest";

import {maintenanceTenantGroupScope} from
  "../../src/external-storage/organization-staff-groups.js";

describe("maintenance directory-sync tenant scope", () => {
  test("AS-1QB-TENANT-SCOPE: tenancy off leaves the maintenance runtime unchanged", () => {
    expect(maintenanceTenantGroupScope({}, false)).toEqual({});
  });

  test("AS-1QB-TENANT-SCOPE: tenancy on protects tenant groups and parses staff paths", () => {
    expect(maintenanceTenantGroupScope({
      ARTIFACT_SERVER_ORG_STAFF_GROUPS: "/TenantWorkspaces/{slug}/{slug}-staff",
    }, true)).toEqual({
      orvexTenantGroupProtection: true,
      organizationStaffGroups: ["/TenantWorkspaces/{slug}/{slug}-staff"],
    });
  });

  test("AS-1QB-TENANT-SCOPE: tenancy on refuses a missing staff definition", () => {
    expect(() => maintenanceTenantGroupScope({}, true)).toThrow(
      "Organization tenancy requires ARTIFACT_SERVER_ORG_STAFF_GROUPS",
    );
  });

  test("AS-1QB-TENANT-SCOPE: tenancy on refuses malformed staff paths", () => {
    expect(() => maintenanceTenantGroupScope({
      ARTIFACT_SERVER_ORG_STAFF_GROUPS: "/TenantWorkspaces/{bad}/staff",
    }, true)).toThrow("ARTIFACT_SERVER_ORG_STAFF_GROUPS entries must be exact group paths");
  });
});
