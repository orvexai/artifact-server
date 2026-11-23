import {createCipheriv, createDecipheriv, createHmac, hkdfSync, randomBytes} from "node:crypto";

const info = Buffer.from("houston-artifacts public-link seal v1", "utf8");

/** Seal a capability secret so managers can copy it again without storing plaintext. */
export function sealPublicLinkSecret(input: {
  readonly installationId: string;
  readonly key: Uint8Array;
  readonly linkId: string;
  readonly generation: number;
  readonly secret: string;
}) {
  const key = deriveKey(input.key, input.installationId);
  const nonce = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, nonce);
  cipher.setAAD(aad(input.installationId, input.linkId, input.generation));
  const ciphertext = Buffer.concat([cipher.update(input.secret, "utf8"), cipher.final()]);
  const packed = Buffer.concat([nonce, ciphertext, cipher.getAuthTag()]);
  return {fingerprint: fingerprint(key), sealed: packed.toString("base64url")};
}

/** Unseal one row using the installation-bound key and link generation. */
export function unsealPublicLinkSecret(input: {
  readonly installationId: string;
  readonly key: Uint8Array;
  readonly linkId: string;
  readonly generation: number;
  readonly sealed: string;
}): string | null {
  try {
    const packed = Buffer.from(input.sealed, "base64url");
    if (packed.length < 29) return null;
    const key = deriveKey(input.key, input.installationId);
    const decipher = createDecipheriv("aes-256-gcm", key, packed.subarray(0, 12));
    decipher.setAAD(aad(input.installationId, input.linkId, input.generation));
    decipher.setAuthTag(packed.subarray(packed.length - 16));
    return Buffer.concat([decipher.update(packed.subarray(12, packed.length - 16)), decipher.final()]).toString("utf8");
  } catch {
    return null;
  }
}

function deriveKey(key: Uint8Array, installationId: string): Buffer {
  return Buffer.from(hkdfSync("sha256", key, Buffer.from(installationId, "utf8"), info, 32));
}

function aad(installationId: string, linkId: string, generation: number): Buffer {
  return Buffer.from(`${installationId}\0${linkId}\0${generation}`, "utf8");
}

function fingerprint(key: Buffer): string {
  return createHmac("sha256", key).update("fingerprint", "utf8").digest("hex").slice(0, 16);
}
