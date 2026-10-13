import {describe, expect, it} from "vitest";

import {parseHeadlessCallbackPaste, terminalLink} from "../../src/cli/cli-oauth-client.js";

describe("authorization URL output", () => {
  const url = "https://auth.example.test/realms/r/protocol/openid-connect/auth?response_type=code&client_id=artifact-server&scope=artifactserver+offline_access";

  it("prints a terminal hyperlink whose visible text is the full URL on a TTY", () => {
    expect(terminalLink(url, {isTTY: true}, {TERM: "xterm-256color"}))
      .toBe(`\u001B]8;;${url}\u001B\\${url}\u001B]8;;\u001B\\`);
  });

  it("prints the plain URL to pipes, files and dumb terminals", () => {
    expect(terminalLink(url, {isTTY: false}, {TERM: "xterm-256color"})).toBe(url);
    expect(terminalLink(url, {}, {})).toBe(url);
    expect(terminalLink(url, {isTTY: true}, {TERM: "dumb"})).toBe(url);
  });
});

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
