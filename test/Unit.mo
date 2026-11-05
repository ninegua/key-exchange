import Blob "mo:core/Blob";
import Debug "mo:core/Debug";
import Nat "mo:core/Nat";
import Principal "mo:core/Principal";
import Result "mo:core/Result";
import Runtime "mo:core/Runtime";
import Text "mo:core/Text";
import Crypto "../src/Crypto";
import State "../src/State";
import Types "../src/Types";

func test(name : Text, body : () -> ()) {
    Debug.print("test: " # name);
    body();
    Debug.print("ok:   " # name);
};

func expect(condition : Bool, message : Text) {
    if (not condition) {
        Runtime.trap(message);
    };
};

func expectBlob(actual : Blob, expected : Blob, message : Text) {
    if (actual != expected) {
        Runtime.trap(message);
    };
};

func expectOk<T>(result : Result.Result<T, Text>, context : Text) : T {
    switch (result) {
        case (#ok(value)) { value };
        case (#err(err)) { Runtime.trap(context # ": " # err) };
    };
};

func expectErr<T>(result : Result.Result<T, Text>, context : Text) {
    switch (result) {
        case (#ok(_)) { Runtime.trap(context # ": expected an error") };
        case (#err(_)) {};
    };
};

func isNull<T>(option : ?T) : Bool {
    switch (option) {
        case (null) { true };
        case (_) { false };
    };
};

let alice = Principal.fromBlob(Blob.fromArray([1]));
let bob = Principal.fromBlob(Blob.fromArray([2]));
let outsider = Principal.fromBlob(Blob.fromArray([3]));

let now : Int = 1_000_000_000;
let sessionId : Nat = 7;

let aliceShareX : Nat = 12_345;
let aliceShareY : Nat = 67_890;
let bobShareX : Nat = 11_111;
let bobShareY : Nat = 22_222;

let aliceTpk = Blob.fromArray([100, 101]);
let bobTpk = Blob.fromArray([200, 201]);

let aliceCtX = Blob.fromArray([10, 11]);
let aliceCtY = Blob.fromArray([12, 13]);
let bobCtX = Blob.fromArray([20, 21]);
let bobCtY = Blob.fromArray([22, 23]);

let aliceEncryptedKey = Blob.fromArray([30, 31]);
let bobEncryptedKey = Blob.fromArray([32, 33]);

func makeCommit(
    id : Nat,
    shareX : Nat,
    shareY : Nat,
    tpk : Blob,
    ctX : Blob,
    ctY : Blob,
    randomnessX : Nat,
    randomnessY : Nat,
) : Types.PartyCommit {
    {
        transport_pk = tpk;
        commitment_x = Crypto.commitment(shareX);
        commitment_y = Crypto.commitment(shareY);
        proof_x = Crypto.proof(shareX, randomnessX, id);
        proof_y = Crypto.proof(shareY, randomnessY, id);
        ciphertext_x = ctX;
        ciphertext_y = ctY;
    };
};

func aliceCommit(id : Nat) : Types.PartyCommit {
    makeCommit(id, aliceShareX, aliceShareY, aliceTpk, aliceCtX, aliceCtY, 501, 502);
};

func bobCommit(id : Nat) : Types.PartyCommit {
    makeCommit(id, bobShareX, bobShareY, bobTpk, bobCtX, bobCtY, 601, 602);
};

func committedSession() : Types.Session {
    let s0 = State.newSession(sessionId, alice, bob, now, 300);
    let s1 = expectOk(State.commitAs(s0, alice, aliceCommit(sessionId), now + 1), "Alice commit");
    expectOk(State.commitAs(s1, bob, bobCommit(sessionId), now + 2), "Bob commit");
};

func abortedSession() : Types.Session {
    let s = committedSession();
    let outcome = expectOk(State.signalAs(s, alice, #abort, now + 3), "abort signal");
    {
        outcome.session with
        alice_encrypted_key = ?aliceEncryptedKey;
        bob_encrypted_key = ?bobEncryptedKey;
    };
};

func revealedSession() : Types.Session {
    let s = committedSession();
    let s1 = expectOk(State.signalAs(s, alice, #reveal, now + 3), "Alice reveal");
    let s2 = expectOk(State.signalAs(s1.session, bob, #reveal, now + 4), "Bob reveal");
    {
        s2.session with
        alice_encrypted_key = ?aliceEncryptedKey;
        bob_encrypted_key = ?bobEncryptedKey;
    };
};

test("commitment and Schnorr proof are valid", func() {
    let commitment = Crypto.commitment(aliceShareX);
    expect(Crypto.verifyShare(commitment, aliceShareX), "commitment should open to its share");
    expect(not Crypto.verifyShare(commitment, aliceShareX + 1), "commitment should reject a different share");

    let proof = Crypto.proof(aliceShareX, 999, sessionId);
    expect(Crypto.verifySchnorr(commitment, proof, sessionId), "valid proof should verify");
    expect(not Crypto.verifySchnorr(commitment, proof, sessionId + 1), "proof should be bound to the session id");

    let badProof : Types.SchnorrProof = { proof with z = Crypto.natToBytes32(1) };
    expect(not Crypto.verifySchnorr(commitment, badProof, sessionId), "tampered proof should fail");
});

test("commitments add to the combined public key", func() {
    let aliceCommitment = Crypto.commitment(aliceShareX);
    let bobCommitment = Crypto.commitment(bobShareX);
    let (?combined) = Crypto.combineCommitments(aliceCommitment, bobCommitment)
        else Runtime.trap("commitments should decode");

    let sum = (aliceShareX + bobShareX) % Crypto.R;
    expect(Crypto.verifyShare(combined, sum), "A_X + B_X should equal g^(a_X + b_X)");
    expect(not Crypto.verifyShare(combined, sum + 1), "combined commitment should reject a different scalar");
});

test("new sessions are undecided and have the expected deadline", func() {
    let s = State.newSession(1, alice, bob, now, 300);
    expect(s.branch == #undecided, "new session should be undecided");
    expect(s.deadline_ns == now + 300 * 1_000_000_000, "deadline should be now + 300 seconds");
    expect(Principal.equal(s.alice, alice), "Alice should be stored");
    expect(Principal.equal(s.bob, bob), "Bob should be stored");
    expect(isNull(s.alice_commit), "Alice should not have committed yet");
    expect(isNull(s.bob_commit), "Bob should not have committed yet");
});

test("commit accepts valid parties and rejects invalid input", func() {
    let s0 = State.newSession(sessionId, alice, bob, now, 300);

    let s1 = expectOk(State.commitAs(s0, alice, aliceCommit(sessionId), now + 1), "Alice commit");
    expectErr(
        State.commitAs(s1, alice, aliceCommit(sessionId), now + 1),
        "duplicate Alice commit",
    );
    expectErr(
        State.commitAs(s0, outsider, aliceCommit(sessionId), now + 1),
        "outsider commit",
    );
    expectErr(
        State.commitAs(s0, alice, aliceCommit(sessionId), s0.deadline_ns),
        "late commit",
    );

    let badProof : Types.PartyCommit = {
        aliceCommit(sessionId) with
        proof_x = Crypto.proof(aliceShareX, 501, sessionId + 1);
    };
    expectErr(
        State.commitAs(s0, alice, badProof, now + 1),
        "invalid proof commit",
    );
});

test("abort is immediate and irrevocable", func() {
    let s = committedSession();
    let outcome = expectOk(State.signalAs(s, alice, #abort, now + 3), "abort signal");
    expect(outcome.session.branch == #abort, "abort should decide the branch");
    switch (outcome.decided) {
        case (?branch) { expect(branch == #abort, "decided branch should be abort") };
        case (null) { Runtime.trap("abort should report a decision") };
    };
    expectErr(
        State.signalAs(outcome.session, bob, #reveal, now + 4),
        "signal after decision",
    );
});

test("reveal requires both parties", func() {
    let s = committedSession();
    let first = expectOk(State.signalAs(s, alice, #reveal, now + 3), "Alice reveal");
    expect(first.session.branch == #undecided, "one reveal should not decide the branch");
    expect(isNull(first.decided), "one reveal should not report a decision");

    let second = expectOk(State.signalAs(first.session, bob, #reveal, now + 4), "Bob reveal");
    expect(second.session.branch == #reveal, "two reveals should decide the branch");
    switch (second.decided) {
        case (?branch) { expect(branch == #reveal, "decided branch should be reveal") };
        case (null) { Runtime.trap("second reveal should report a decision") };
    };
});

test("signals are rejected for outsiders and after the deadline", func() {
    let s = committedSession();
    expectErr(
        State.signalAs(s, outsider, #reveal, now + 3),
        "outsider signal",
    );
    expectErr(
        State.signalAs(s, outsider, #reveal, s.deadline_ns),
        "outsider signal after deadline",
    );

    let outcome = expectOk(State.signalAs(s, bob, #reveal, s.deadline_ns), "deadline signal");
    expect(outcome.session.branch == #abort, "deadline should force abort");
});

test("deadline only aborts undecided sessions", func() {
    let s = State.newSession(sessionId, alice, bob, now, 300);
    expect(isNull(State.deadlineAbort(s, s.deadline_ns - 1)), "deadline should not fire early");
    switch (State.deadlineAbort(s, s.deadline_ns)) {
        case (?aborted) { expect(aborted.branch == #abort, "deadline should set abort") };
        case (null) { Runtime.trap("deadline should fire") };
    };

    let revealed = revealedSession();
    expect(
        isNull(State.deadlineAbort(revealed, revealed.deadline_ns + 1)),
        "deadline should not change a revealed session",
    );
});

test("finalization selects the branch-specific identities", func() {
    let s = committedSession();
    expect(isNull(State.selectFinalization(s)), "undecided session should not finalize");

    let abort = abortedSession();
    let (?abortFin) = State.selectFinalization(abort) else Runtime.trap("abort finalization missing");
    expectBlob(
        abortFin.alice_identity,
        Text.encodeUtf8(State.IDENTITY_ABORT_ALICE),
        "abort Alice identity",
    );
    expectBlob(
        abortFin.bob_identity,
        Text.encodeUtf8(State.IDENTITY_ABORT_BOB),
        "abort Bob identity",
    );
    expectBlob(abortFin.alice_transport_pk, aliceTpk, "abort Alice transport key");
    expectBlob(abortFin.bob_transport_pk, bobTpk, "abort Bob transport key");

    let reveal = revealedSession();
    let (?revealFin) = State.selectFinalization(reveal) else Runtime.trap("reveal finalization missing");
    expectBlob(
        revealFin.alice_identity,
        Text.encodeUtf8(State.IDENTITY_REVEAL_ALICE),
        "reveal Alice identity",
    );
    expectBlob(
        revealFin.bob_identity,
        Text.encodeUtf8(State.IDENTITY_REVEAL_BOB),
        "reveal Bob identity",
    );
});

test("finalization requires both commits", func() {
    let s0 = State.newSession(sessionId, alice, bob, now, 300);
    let s1 = expectOk(State.commitAs(s0, alice, aliceCommit(sessionId), now + 1), "Alice commit");
    let outcome = expectOk(State.signalAs(s1, alice, #abort, now + 2), "abort with one commit");
    expect(
        isNull(State.selectFinalization(outcome.session)),
        "session with only one commit should not finalize",
    );
});

test("share packages contain the correct counterparty data", func() {
    let abort = abortedSession();
    let (?aliceAbort) = State.selectSharePackage(abort, alice) else Runtime.trap("Alice abort package missing");
    expectBlob(aliceAbort.identity, Text.encodeUtf8(State.IDENTITY_ABORT_ALICE), "Alice abort identity");
    expectBlob(aliceAbort.encrypted_vetkey, aliceEncryptedKey, "Alice should receive her encrypted VetKey");
    expectBlob(aliceAbort.counterparty_ciphertext, bobCtX, "Alice should receive Bob's X ciphertext");
    expectBlob(
        aliceAbort.counterparty_commitment,
        Crypto.commitment(bobShareX),
        "Alice should verify Bob's X commitment",
    );

    let (?bobAbort) = State.selectSharePackage(abort, bob) else Runtime.trap("Bob abort package missing");
    expectBlob(bobAbort.identity, Text.encodeUtf8(State.IDENTITY_ABORT_BOB), "Bob abort identity");
    expectBlob(bobAbort.encrypted_vetkey, bobEncryptedKey, "Bob should receive his encrypted VetKey");
    expectBlob(bobAbort.counterparty_ciphertext, aliceCtY, "Bob should receive Alice's Y ciphertext");
    expectBlob(
        bobAbort.counterparty_commitment,
        Crypto.commitment(aliceShareY),
        "Bob should verify Alice's Y commitment",
    );

    let reveal = revealedSession();
    let (?aliceReveal) = State.selectSharePackage(reveal, alice) else Runtime.trap("Alice reveal package missing");
    expectBlob(aliceReveal.identity, Text.encodeUtf8(State.IDENTITY_REVEAL_ALICE), "Alice reveal identity");
    expectBlob(aliceReveal.counterparty_ciphertext, bobCtY, "Alice should receive Bob's Y ciphertext");
    expectBlob(
        aliceReveal.counterparty_commitment,
        Crypto.commitment(bobShareY),
        "Alice should verify Bob's Y commitment",
    );

    let (?bobReveal) = State.selectSharePackage(reveal, bob) else Runtime.trap("Bob reveal package missing");
    expectBlob(bobReveal.identity, Text.encodeUtf8(State.IDENTITY_REVEAL_BOB), "Bob reveal identity");
    expectBlob(bobReveal.counterparty_ciphertext, aliceCtX, "Bob should receive Alice's X ciphertext");
    expectBlob(
        bobReveal.counterparty_commitment,
        Crypto.commitment(aliceShareX),
        "Bob should verify Alice's X commitment",
    );
});

test("share packages are unavailable before a decision or to outsiders", func() {
    let s = committedSession();
    expect(isNull(State.selectSharePackage(s, alice)), "undecided session should not expose a package");
    expect(isNull(State.selectSharePackage(abortedSession(), outsider)), "outsider should not get a package");
});

Debug.print("ALL UNIT TESTS PASSED");
