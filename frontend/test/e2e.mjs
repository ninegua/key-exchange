// End-to-end test for the frontend crypto and canister protocol.
// Run through ../../scripts/test-e2e.sh, which starts the local `test` network,
// deploys the canister, and passes CANISTER_ID / IC_ROOT_KEY / IC_HOST.
import { Actor, HttpAgent } from "@icp-sdk/core/agent";
import { Ed25519KeyIdentity } from "@icp-sdk/core/identity";
import {
  DerivedPublicKey,
  EncryptedVetKey,
  IbeCiphertext,
  IbeIdentity,
  IbeSeed,
  TransportSecretKey,
} from "@icp-sdk/vetkeys";

import { idlFactory } from "../src/bindings/declarations/key_exchange.did.js";
import {
  IDENTITY,
  addShares,
  bigIntToBytes32,
  bytesToBigInt,
  commitmentFor,
  publicKeyFor,
  randomScalar,
  schnorrProof,
  verifyCommitment,
} from "../src/protocol.js";

const canisterId = process.env.CANISTER_ID;
const rootKey = Uint8Array.from(Buffer.from(process.env.IC_ROOT_KEY ?? "", "hex"));
const host = process.env.IC_HOST ?? "http://localhost:18080";
if (!canisterId || rootKey.length === 0) {
  throw new Error("CANISTER_ID and IC_ROOT_KEY are required");
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function makeActor(identity) {
  const agent = await HttpAgent.create({ host, identity, rootKey });
  return Actor.createActor(idlFactory, { agent, canisterId });
}

function unwrap(result, context) {
  if ("ok" in result) return result.ok;
  throw new Error(`${context}: ${result.err}`);
}

function makeCommit(sessionId, role, tsk, dpk, shares) {
  const identities =
    role === "alice"
      ? { x: IDENTITY.revealBob, y: IDENTITY.abortBob }
      : { x: IDENTITY.abortAlice, y: IDENTITY.revealAlice };

  return {
    commitmentX: commitmentFor(shares.x),
    commitmentY: commitmentFor(shares.y),
    proofX: schnorrProof(shares.x, randomScalar(), sessionId),
    proofY: schnorrProof(shares.y, randomScalar(), sessionId),
    ciphertextX: IbeCiphertext.encrypt(
      dpk,
      IbeIdentity.fromString(identities.x),
      bigIntToBytes32(shares.x),
      IbeSeed.random(),
    ).serialize(),
    ciphertextY: IbeCiphertext.encrypt(
      dpk,
      IbeIdentity.fromString(identities.y),
      bigIntToBytes32(shares.y),
      IbeSeed.random(),
    ).serialize(),
    transportPk: tsk.publicKeyBytes(),
  };
}

async function waitClosed(identity, sessionId) {
  for (let i = 0; i < 40; i += 1) {
    const actor = await makeActor(identity);
    const result = await actor.get_session(sessionId);
    const session = result.length ? result[0] : null;
    if (session?.closed) return session;
    await sleep(500);
  }
  throw new Error("timed out waiting for finalization");
}

async function decryptPackage(actor, sessionId, tsk, dpk, ownShare, expectedSk, label) {
  const pkg = unwrap(await actor.get_encrypted_share(sessionId), `${label} package`);
  const vetKey = EncryptedVetKey.deserialize(pkg.encrypted_vetkey).decryptAndVerify(
    tsk,
    dpk,
    pkg.identity,
  );
  const counterpartyShare = bytesToBigInt(
    IbeCiphertext.deserialize(pkg.counterparty_ciphertext).decrypt(vetKey),
  );

  if (!verifyCommitment(pkg.counterparty_commitment, counterpartyShare)) {
    throw new Error(`${label}: counterparty share does not match commitment`);
  }

  const secret = addShares(ownShare, counterpartyShare);
  if (secret !== expectedSk) {
    throw new Error(`${label}: derived the wrong private key`);
  }

  return {
    publicKey: publicKeyFor(secret),
    counterpartyShare,
  };
}

async function run(branch) {
  const aliceIdentity = Ed25519KeyIdentity.generate();
  const bobIdentity = Ed25519KeyIdentity.generate();
  const aliceActor = await makeActor(aliceIdentity);
  const bobActor = await makeActor(bobIdentity);

  const verificationKey = Uint8Array.from(await aliceActor.get_verification_key());
  const dpk = DerivedPublicKey.deserialize(verificationKey);

  const aliceShares = { x: randomScalar(), y: randomScalar() };
  const bobShares = { x: randomScalar(), y: randomScalar() };
  const aliceTsk = TransportSecretKey.random();
  const bobTsk = TransportSecretKey.random();

  const sessionId = await aliceActor.create_session(
    bobIdentity.getPrincipal(),
    300n,
  );
  const aliceCommit = makeCommit(sessionId, "alice", aliceTsk, dpk, aliceShares);
  const bobCommit = makeCommit(sessionId, "bob", bobTsk, dpk, bobShares);

  unwrap(
    await aliceActor.commit(
      sessionId,
      aliceCommit.transportPk,
      aliceCommit.commitmentX,
      aliceCommit.commitmentY,
      aliceCommit.proofX,
      aliceCommit.proofY,
      aliceCommit.ciphertextX,
      aliceCommit.ciphertextY,
    ),
    "alice commit",
  );
  unwrap(
    await bobActor.commit(
      sessionId,
      bobCommit.transportPk,
      bobCommit.commitmentX,
      bobCommit.commitmentY,
      bobCommit.proofX,
      bobCommit.proofY,
      bobCommit.ciphertextX,
      bobCommit.ciphertextY,
    ),
    "bob commit",
  );

  if (branch === "abort") {
    unwrap(await aliceActor.signal(sessionId, { abort: null }), "alice abort");
  } else {
    unwrap(await aliceActor.signal(sessionId, { reveal: null }), "alice reveal");
    unwrap(await bobActor.signal(sessionId, { reveal: null }), "bob reveal");
  }

  await waitClosed(aliceIdentity, sessionId);

  let aliceResult;
  let bobResult;
  if (branch === "abort") {
    aliceResult = await decryptPackage(
      aliceActor,
      sessionId,
      aliceTsk,
      dpk,
      aliceShares.x,
      addShares(aliceShares.x, bobShares.x),
      "Alice abort",
    );
    bobResult = await decryptPackage(
      bobActor,
      sessionId,
      bobTsk,
      dpk,
      bobShares.y,
      addShares(aliceShares.y, bobShares.y),
      "Bob abort",
    );
  } else {
    aliceResult = await decryptPackage(
      aliceActor,
      sessionId,
      aliceTsk,
      dpk,
      aliceShares.y,
      addShares(aliceShares.y, bobShares.y),
      "Alice reveal",
    );
    bobResult = await decryptPackage(
      bobActor,
      sessionId,
      bobTsk,
      dpk,
      bobShares.x,
      addShares(bobShares.x, aliceShares.x),
      "Bob reveal",
    );
  }

  console.log(
    `${branch}: session ${sessionId} OK ` +
      `(alice ${Buffer.from(aliceResult.publicKey).toString("hex").slice(0, 16)}…, ` +
      `bob ${Buffer.from(bobResult.publicKey).toString("hex").slice(0, 16)}…)`,
  );
}

await run("abort");
await run("reveal");
console.log("FRONTEND E2E PASSED");
