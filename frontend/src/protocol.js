import { bls12_381 } from "@noble/curves/bls12-381";
import { sha256 } from "@noble/hashes/sha256";

export const SCALAR_ORDER = bls12_381.G2.CURVE.n;

export const IDENTITY = {
  abortAlice: "fair_exchange_v1/abort/alice/b_X",
  abortBob: "fair_exchange_v1/abort/bob/a_Y",
  revealAlice: "fair_exchange_v1/reveal/alice/b_Y",
  revealBob: "fair_exchange_v1/reveal/bob/a_X",
};

const encoder = new TextEncoder();

export function utf8(text) {
  return encoder.encode(text);
}

export function concatBytes(...parts) {
  const length = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

export function bytesToBigInt(bytes) {
  let value = 0n;
  for (const byte of bytes) {
    value = (value << 8n) | BigInt(byte);
  }
  return value;
}

export function bigIntToBytes(value, length) {
  let hex = value.toString(16);
  if (hex.length > length * 2) {
    throw new Error(`integer does not fit in ${length} bytes`);
  }
  hex = hex.padStart(length * 2, "0");
  const out = new Uint8Array(length);
  for (let i = 0; i < length; i += 1) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export function bigIntToBytes32(value) {
  return bigIntToBytes(value, 32);
}

export function bytesToHex(bytes) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}

export function randomScalar() {
  const raw = crypto.getRandomValues(new Uint8Array(32));
  const scalar = bytesToBigInt(raw) % SCALAR_ORDER;
  return scalar === 0n ? 1n : scalar;
}

// The Motoko bls12-381 package uses EIP-2537 uncompressed encoding:
// each Fp element is 64-byte big-endian, and G2 is x.c0, x.c1, y.c0, y.c1.
export function pointToMotokoBytes(point) {
  const affine = point.toAffine();
  return concatBytes(
    bigIntToBytes(affine.x.c0, 64),
    bigIntToBytes(affine.x.c1, 64),
    bigIntToBytes(affine.y.c0, 64),
    bigIntToBytes(affine.y.c1, 64),
  );
}

export function commitmentFor(share) {
  const point = bls12_381.G2.Point.BASE.multiply(share % SCALAR_ORDER);
  return pointToMotokoBytes(point);
}

export function verifyCommitment(commitmentBytes, share) {
  return bytesEqual(commitmentFor(share), commitmentBytes);
}

export function motokoBytesToPoint(bytes) {
  if (bytes.length !== 256) {
    throw new Error("expected a 256-byte uncompressed G2 point");
  }
  const fp = (offset) => bytesToBigInt(bytes.slice(offset, offset + 64));
  return bls12_381.G2.Point.fromAffine({
    x: { c0: fp(0), c1: fp(64) },
    y: { c0: fp(128), c1: fp(192) },
  });
}

export function combineCommitmentBytes(a, b) {
  return pointToMotokoBytes(motokoBytesToPoint(a).add(motokoBytesToPoint(b)));
}

export function challengeFor(sessionId, commitmentBytes, rBytes) {
  const digest = sha256(
    concatBytes(
      utf8("fair_exchange_v1/schnorr"),
      utf8(String(sessionId)),
      commitmentBytes,
      rBytes,
    ),
  );
  return bytesToBigInt(digest) % SCALAR_ORDER;
}

export function schnorrProof(share, randomness, sessionId) {
  const rPoint = bls12_381.G2.Point.BASE.multiply(randomness % SCALAR_ORDER);
  const rBytes = pointToMotokoBytes(rPoint);
  const c = challengeFor(sessionId, commitmentFor(share), rBytes);
  const z = (randomness + c * (share % SCALAR_ORDER)) % SCALAR_ORDER;
  return {
    r: rBytes,
    z: bigIntToBytes32(z),
  };
}

export function addShares(a, b) {
  return (a + b) % SCALAR_ORDER;
}

export function publicKeyFor(share) {
  return pointToMotokoBytes(bls12_381.G2.Point.BASE.multiply(share % SCALAR_ORDER));
}
