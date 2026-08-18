import { createHmac, timingSafeEqual } from "node:crypto";

export const CLIENT_PROOF_DOMAIN = "codex-agent-mesh\0client-proof-v1\0";
export const SERVER_PROOF_DOMAIN = "codex-agent-mesh\0server-proof-v1\0";

export type TranscriptField = readonly [name: string, value: string];

function lengthPrefixed(value: string): Buffer {
  const bytes = Buffer.from(value, "utf8");
  const prefix = Buffer.allocUnsafe(4);
  prefix.writeUInt32LE(bytes.byteLength);
  return Buffer.concat([prefix, bytes]);
}

/** Encodes the shared fixed-order handshake transcript; field names are documentary. */
export function encodeTranscript(fields: readonly TranscriptField[]): Buffer {
  return Buffer.concat(fields.map(([, value]) => lengthPrefixed(value)));
}

export function clientProof(
  material: Uint8Array,
  fields: readonly TranscriptField[],
): string {
  return createHmac("sha256", material)
    .update(CLIENT_PROOF_DOMAIN, "utf8")
    .update(encodeTranscript(fields))
    .digest("hex");
}

export function serverProof(
  material: Uint8Array,
  fields: readonly TranscriptField[],
  clientProofHex: string,
): string {
  return createHmac("sha256", material)
    .update(SERVER_PROOF_DOMAIN, "utf8")
    .update(encodeTranscript(fields))
    .update(lengthPrefixed(clientProofHex))
    .digest("hex");
}

export function verifyProof(expectedHex: string, actualHex: string): boolean {
  if (!/^[a-f0-9]{64}$/.test(expectedHex) || !/^[a-f0-9]{64}$/.test(actualHex))
    return false;
  return timingSafeEqual(
    Buffer.from(expectedHex, "hex"),
    Buffer.from(actualHex, "hex"),
  );
}
