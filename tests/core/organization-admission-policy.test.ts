import {describe, expect, test} from "vitest";

import {parseOrganizationAdmissionPolicyJson} from
  "../../src/external-storage/organization-registry.js";

describe("organization admission policy", () => {
  test("org create policy rejects a bare group selector", () => {
    expect(() => parseOrganizationAdmissionPolicyJson(JSON.stringify({
      groupRoots: ["/org-b/"],
      seed: [{role: "administrator", selector: "admins"}],
    }))).toThrow("full group paths");
  });

  test("org create accepts only a full group selector beneath its roots", () => {
    expect(parseOrganizationAdmissionPolicyJson(JSON.stringify({
      groupRoots: ["/org-b/"],
      seed: [{role: "administrator", selector: "/org-b/admins"}],
    }))).toMatchObject({seed: [{selector: "/org-b/admins"}]});
    expect(() => parseOrganizationAdmissionPolicyJson(JSON.stringify({
      groupRoots: ["/org-b/"],
      seed: [{role: "administrator", selector: "/org-a/admins"}],
    }))).toThrow("full group paths");
  });
});
