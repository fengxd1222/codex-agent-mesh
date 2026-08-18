import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
  clientProof,
  encodeTranscript,
  serverProof,
  verifyProof,
} from "../dist/handshake.js";

const vectorPath = new URL(
  "../../../protocol/v1/handshake-vectors.json",
  import.meta.url,
);

test("handshake transcript and mutual proofs match the shared vector", async () => {
  const [vector] = JSON.parse(await readFile(vectorPath, "utf8"));
  const material = Buffer.from(vector.test_hmac_material_hex, "hex");
  assert.equal(
    encodeTranscript(vector.fields).toString("hex"),
    vector.transcript_hex,
  );
  const client = clientProof(material, vector.fields);
  assert.equal(client, vector.client_proof);
  const server = serverProof(material, vector.fields, client);
  assert.equal(server, vector.server_proof);
  assert.equal(verifyProof(vector.server_proof, server), true);
  const changedLastNibble = server.endsWith("0") ? "1" : "0";
  assert.equal(
    verifyProof(
      vector.server_proof,
      `${server.slice(0, -1)}${changedLastNibble}`,
    ),
    false,
  );
});
