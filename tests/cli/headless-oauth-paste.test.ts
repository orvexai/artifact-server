import {describe, expect, it} from "vitest";

import {parseHeadlessCallbackPaste} from "../../src/cli/cli-oauth-client.js";

describe("headless OAuth paste-back", () => {
  const state = "0123456789abcdef0123456789abcdef";

  it("accepts an authorization code and binds it to the locally generated state", () => {
    expect(parseHeadlessCallbackPaste("authorization-code", state)).toEqual({
      code: "authorization-code",
      state,
    });
  });

  it("accepts a complete loopback redirect and preserves issuer", () => {
    expect(parseHeadlessCallbackPaste(
      `http://127.0.0.1:45678/oauth/callback?code=authorization-code&state=${state}&iss=https%3A%2F%2Fidp.example.test`,
      state,
    )).toEqual({
      code: "authorization-code",
      iss: "https://idp.example.test",
      state,
    });
  });

  it("rejects a pasted redirect with a different state", () => {
    expect(() => parseHeadlessCallbackPaste(
      "http://127.0.0.1:45678/oauth/callback?code=authorization-code&state=ffffffffffffffff",
      state,
    )).toThrow("invalid");
  });
});
