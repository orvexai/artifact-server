import {describe, expect, test} from "vitest";

import {sealPublicLinkSecret, unsealPublicLinkSecret} from
  "../../src/application/public-link-seal.js";

describe("public-link capability sealing", () => {
  test("seals a random 32-byte URL secret with installation-scoped authenticated encryption", () => {
    const key = Buffer.alloc(32, 4);
    const secret = Buffer.alloc(32, 8).toString("base64url");
    const sealed = sealPublicLinkSecret({
      installationId: "installation-a",
      key,
      linkId: "link-a",
      generation: 3,
      secret,
    });

    expect(Buffer.from(secret, "base64url")).toHaveLength(32);
    expect(unsealPublicLinkSecret({
      installationId: "installation-a",
      key,
      linkId: "link-a",
      generation: 3,
      sealed: sealed.sealed,
    })).toBe(secret);
  });

  test("PLK-005-F rejects ciphertext moved across installations, links, or generations", () => {
    const key = Buffer.alloc(32, 7);
    const link = {
      installationId: "tenant-a",
      key,
      linkId: "link-1",
      generation: 1,
      secret: Buffer.alloc(32, 9).toString("base64url"),
    };
    const sealed = sealPublicLinkSecret(link);
    expect(unsealPublicLinkSecret({...link, sealed: sealed.sealed})).toBe(link.secret);
    expect(unsealPublicLinkSecret({...link, installationId: "tenant-b", sealed: sealed.sealed})).toBeNull();
    expect(unsealPublicLinkSecret({...link, linkId: "link-2", sealed: sealed.sealed})).toBeNull();
    expect(unsealPublicLinkSecret({...link, generation: 2, sealed: sealed.sealed})).toBeNull();
    const tampered = `${sealed.sealed[0] === "A" ? "B" : "A"}${sealed.sealed.slice(1)}`;
    expect(unsealPublicLinkSecret({...link, sealed: tampered})).toBeNull();
  });
});
