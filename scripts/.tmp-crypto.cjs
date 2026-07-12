"use strict";
var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
  // If the importer is in node compatibility mode or this is not an ESM
  // file that has been converted to a CommonJS file using a Babel-
  // compatible transform (i.e. "__esModule" has not been set), then set
  // "default" to the CommonJS "module.exports" for node compatibility.
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/crypto.ts
var crypto_exports = {};
__export(crypto_exports, {
  clearSharedKey: () => clearSharedKey,
  decryptEnvelope: () => decryptEnvelope,
  deriveSharedKey: () => deriveSharedKey,
  destroyE2E: () => destroyE2E,
  encryptInner: () => encryptInner,
  generateKeypair: () => generateKeypair,
  newE2EState: () => newE2EState
});
module.exports = __toCommonJS(crypto_exports);
var import_node_crypto = __toESM(require("node:crypto"));

// ../shared/protocol.ts
var PROTOCOL_VERSION = "v2";
function aadFor(senderRole, seq) {
  return new TextEncoder().encode(`${PROTOCOL_VERSION}|${senderRole}|${seq}`);
}

// src/crypto.ts
var HKDF_INFO = Buffer.from("dispatch-freebuff-e2e-v1", "utf8");
var HKDF_SALT = Buffer.alloc(32, 0);
var CURVE = "prime256v1";
function generateKeypair() {
  const kp = import_node_crypto.default.generateKeyPairSync("ec", { namedCurve: CURVE });
  const jwk = kp.publicKey.export({ format: "jwk" });
  if (jwk.crv !== "P-256") jwk.crv = "P-256";
  return { kp, jwk, jwkJson: JSON.stringify(jwk) };
}
function newE2EState() {
  const { kp, jwk, jwkJson } = generateKeypair();
  return { kp, jwk, jwkJson, sharedKey: null, outSeq: 0, inSeq: 0 };
}
function deriveSharedKey(myPrivate, peerJwk) {
  if (peerJwk.crv !== "P-256") peerJwk.crv = "P-256";
  const peerPub = import_node_crypto.default.createPublicKey({ key: peerJwk, format: "jwk" });
  const sharedBits = import_node_crypto.default.diffieHellman({ privateKey: myPrivate, publicKey: peerPub });
  console.error(`[daemon-e2e-diag] clientKey x prefix=${(peerJwk.x || "").slice(0, 16)}... (crv=${peerJwk.crv})`);
  console.error(`[daemon-e2e-diag] sharedBits len=${sharedBits.length} hex=${sharedBits.toString("hex")}`);
  const key = import_node_crypto.default.hkdfSync("sha256", sharedBits, HKDF_SALT, HKDF_INFO, 32);
  console.error(`[daemon-e2e-diag] aesKey hex=${Buffer.from(key).toString("hex")}`);
  try {
    const probeNonce = Buffer.alloc(12, 0);
    const probePlain = Buffer.from("E2E_PROBE", "utf8");
    const probeAad = Buffer.from("v2|client|999", "utf8");
    const probeCipher = import_node_crypto.default.createCipheriv("aes-256-gcm", Buffer.from(key), probeNonce);
    probeCipher.setAAD(probeAad);
    const probeEnc = Buffer.concat([probeCipher.update(probePlain), probeCipher.final()]);
    const probeTag = probeCipher.getAuthTag();
    const probeCt = Buffer.concat([probeEnc, probeTag]).toString("hex");
    console.error(`[daemon-e2e-diag] probeCiphertext=${probeCt}`);
  } catch (e) {
    console.error(`[daemon-e2e-diag] probe encrypt failed: ${e.message}`);
  }
  sharedBits.fill(0);
  return Buffer.from(key);
}
function encryptInner(state, senderRole, inner) {
  if (!state.sharedKey) throw new Error("E2E: cannot encrypt before key exchange");
  state.outSeq += 1;
  const nonce = import_node_crypto.default.randomBytes(12);
  const aad = aadFor(senderRole, state.outSeq);
  const plain = Buffer.from(JSON.stringify(inner), "utf8");
  const cipher = import_node_crypto.default.createCipheriv("aes-256-gcm", state.sharedKey, nonce);
  cipher.setAAD(aad);
  const enc = Buffer.concat([cipher.update(plain), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    v: 2,
    type: "enc",
    seq: state.outSeq,
    nonce: nonce.toString("base64"),
    // ciphertext + 16-byte auth tag (node convention)
    ct: Buffer.concat([enc, tag]).toString("base64")
  };
}
function decryptEnvelope(state, senderRole, env) {
  if (env.v !== 2 || env.type !== "enc") throw new Error("E2E: not an enc envelope");
  if (!state.sharedKey) throw new Error("E2E: cannot decrypt before key exchange");
  if (!Number.isInteger(env.seq) || env.seq <= 0) throw new Error("E2E: bad seq");
  if (env.seq <= state.inSeq) return null;
  const nonce = Buffer.from(env.nonce, "base64");
  const ctWithTag = Buffer.from(env.ct, "base64");
  if (ctWithTag.length < 17) throw new Error("E2E: ct too short");
  const tag = ctWithTag.subarray(ctWithTag.length - 16);
  const data = ctWithTag.subarray(0, ctWithTag.length - 16);
  const aad = aadFor(senderRole, env.seq);
  const decipher = import_node_crypto.default.createDecipheriv("aes-256-gcm", state.sharedKey, nonce);
  decipher.setAAD(aad);
  decipher.setAuthTag(tag);
  const plain = Buffer.concat([decipher.update(data), decipher.final()]);
  state.inSeq = env.seq;
  return JSON.parse(plain.toString("utf8"));
}
function clearSharedKey(state) {
  if (state.sharedKey) state.sharedKey.fill(0);
  state.sharedKey = null;
  state.inSeq = 0;
  state.outSeq = 0;
}
function destroyE2E(state) {
  clearSharedKey(state);
}
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  clearSharedKey,
  decryptEnvelope,
  deriveSharedKey,
  destroyE2E,
  encryptInner,
  generateKeypair,
  newE2EState
});
