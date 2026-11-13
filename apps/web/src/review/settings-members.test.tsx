import {createElement} from "react";
import {renderToStaticMarkup} from "react-dom/server";
import {describe, expect, test} from "vitest";

import {MembersScreen} from "./settings-members";

describe("member settings", () => {
  test("hides manual admission when the identity provider manages organization membership", () => {
    const tenant = renderToStaticMarkup(createElement(MembersScreen, {
      canAdmit: false,
      canManage: true,
      showEmails: true,
      showRoles: true,
    }));
    const standalone = renderToStaticMarkup(createElement(MembersScreen, {
      canAdmit: true,
      canManage: true,
      showEmails: true,
      showRoles: true,
    }));

    expect(tenant).not.toContain("Admit member");
    expect(tenant).toContain("Organization membership is managed by your identity provider.");
    expect(standalone).toContain("Admit member");
  });
});
