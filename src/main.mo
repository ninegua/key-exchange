import Blob "mo:core/Blob";
import Debug "mo:core/Debug";
import Int "mo:core/Int";
import Map "mo:core/Map";
import Nat "mo:core/Nat";
import Principal "mo:core/Principal";
import Result "mo:core/Result";
import Runtime "mo:core/Runtime";
import Text "mo:core/Text";
import Time "mo:core/Time";
import Timer "mo:core/Timer";
import ManagementCanister "./ic_vetkeys/ManagementCanister";
import State "./State";
import Types "./Types";

persistent actor {
    public type SchnorrProof = Types.SchnorrProof;
    public type PartyCommit = Types.PartyCommit;
    public type Branch = Types.Branch;
    public type Signal = Types.Signal;
    public type Session = Types.Session;
    public type SharePackage = Types.SharePackage;

    let sessions = Map.empty<Nat, Session>();
    var next_session_id : Nat = 1;

    let keyName = Runtime.envVar<system>("VETKD_KEY_NAME") ?? "test_key_1";
    let keyId : ManagementCanister.VetKdKeyid = {
        curve = #bls12_381_g2;
        name = keyName;
    };
    let context = Text.encodeUtf8("fair_exchange_v1");

    public shared ({ caller }) func create_session(
        counterparty : Principal,
        deadline_seconds : Nat,
    ) : async Nat {
        if (Principal.isAnonymous(caller)) {
            Runtime.trap("anonymous caller");
        };
        if (Principal.equal(caller, counterparty)) {
            Runtime.trap("counterparty must differ");
        };

        let id = next_session_id;
        next_session_id += 1;

        let session = State.newSession(
            id,
            caller,
            counterparty,
            Time.now(),
            deadline_seconds,
        );
        Map.add(sessions, Nat.compare, id, session);
        scheduleDeadline<system>(id, deadline_seconds);
        id;
    };

    public shared ({ caller }) func commit(
        session_id : Nat,
        transport_pk : Blob,
        commitment_x : Blob,
        commitment_y : Blob,
        proof_x : SchnorrProof,
        proof_y : SchnorrProof,
        ciphertext_x : Blob,
        ciphertext_y : Blob,
    ) : async Result.Result<(), Text> {
        let (?session) = Map.get(sessions, Nat.compare, session_id)
            else return #err("unknown session");

        let commit : PartyCommit = {
            transport_pk;
            commitment_x;
            commitment_y;
            proof_x;
            proof_y;
            ciphertext_x;
            ciphertext_y;
        };

        switch (State.commitAs(session, caller, commit, Time.now())) {
            case (#err(err)) { #err(err) };
            case (#ok(updated)) {
                Map.add(sessions, Nat.compare, session_id, updated);
                #ok(());
            };
        };
    };

    public shared ({ caller }) func signal(
        session_id : Nat,
        signal : Signal,
    ) : async Result.Result<(), Text> {
        let (?session) = Map.get(sessions, Nat.compare, session_id)
            else return #err("unknown session");

        switch (State.signalAs(session, caller, signal, Time.now())) {
            case (#err(err)) { #err(err) };
            case (#ok(outcome)) {
                Map.add(sessions, Nat.compare, session_id, outcome.session);
                switch (outcome.decided) {
                    case (?branch) {
                        Debug.print(
                            "signal: decision for session " # Nat.toText(session_id) #
                            " branch " # debug_show(branch)
                        );
                        await finalize(session_id);
                    };
                    case (null) {};
                };
                #ok(());
            };
        };
    };

    public shared query ({ caller }) func get_encrypted_share(
        session_id : Nat,
    ) : async Result.Result<SharePackage, Text> {
        let (?session) = Map.get(sessions, Nat.compare, session_id)
            else return #err("unknown session");

        if (not session.closed) {
            return #err("session not finalized");
        };

        switch (State.selectSharePackage(session, caller)) {
            case (?pkg) { #ok(pkg) };
            case (null) { #err("not authorized or share unavailable") };
        };
    };

    public shared func get_verification_key() : async Blob {
        await ManagementCanister.vetKdPublicKey(null, context, keyId);
    };

    public shared query func get_session(session_id : Nat) : async ?Session {
        Map.get(sessions, Nat.compare, session_id);
    };

    private func finalize(session_id : Nat) : async () {
        let (?session) = Map.get(sessions, Nat.compare, session_id)
            else {
                Debug.print("finalize: session " # Nat.toText(session_id) # " not found");
                return;
            };

        Debug.print(
            "finalize: session " # Nat.toText(session_id) #
            " closed=" # debug_show(session.closed) #
            " branch=" # debug_show(session.branch) #
            " aliceCommit=" # debug_show(session.alice_commit != null) #
            " bobCommit=" # debug_show(session.bob_commit != null)
        );

        if (session.closed) { return };

        let (?fin) = State.selectFinalization(session) else {
            Debug.print("finalize: selectFinalization returned null for session " # Nat.toText(session_id));
            return;
        };

        Debug.print("finalize: starting Alice derivation for session " # Nat.toText(session_id));
        // Start both derivations before awaiting either one, so the two
        // management-canister calls are in flight concurrently.
        let aliceKeyPromise = ManagementCanister.vetKdDeriveKey(
            fin.alice_identity,
            context,
            keyId,
            fin.alice_transport_pk,
        );
        Debug.print("finalize: starting Bob derivation for session " # Nat.toText(session_id));
        let bobKeyPromise = ManagementCanister.vetKdDeriveKey(
            fin.bob_identity,
            context,
            keyId,
            fin.bob_transport_pk,
        );
        Debug.print("finalize: awaiting Alice derivation for session " # Nat.toText(session_id));
        let aliceEncryptedKey = await aliceKeyPromise;
        Debug.print("finalize: Alice derivation done for session " # Nat.toText(session_id));
        Debug.print("finalize: awaiting Bob derivation for session " # Nat.toText(session_id));
        let bobEncryptedKey = await bobKeyPromise;
        Debug.print("finalize: Bob derivation done for session " # Nat.toText(session_id));

        let (?latest) = Map.get(sessions, Nat.compare, session_id) else return;
        Map.add(sessions, Nat.compare, session_id, {
            latest with
            alice_encrypted_key = ?aliceEncryptedKey;
            bob_encrypted_key = ?bobEncryptedKey;
            closed = true;
        });
        Debug.print("finalize: stored keys and closed session " # Nat.toText(session_id));
    };

    private func scheduleDeadline<system>(session_id : Nat, seconds : Nat) {
        ignore Timer.setTimer<system>(#seconds seconds, func() : async () {
            await handleDeadline(session_id);
        });
    };

    private func handleDeadline(session_id : Nat) : async () {
        switch (Map.get(sessions, Nat.compare, session_id)) {
            case (?session) {
                switch (State.deadlineAbort(session, Time.now())) {
                    case (?updated) {
                        Map.add(sessions, Nat.compare, session_id, updated);
                        await finalize(session_id);
                    };
                    case (null) {};
                };
            };
            case (null) {};
        };
    };

    system func postupgrade() {
        // With moc 1.15.0 this is the upgrade hook; newer compilers may prefer
        // migration functions.
        let now = Time.now();
        for ((id, session) in Map.entries(sessions)) {
            switch (session.branch) {
                case (#undecided) {
                    let delay = Int.abs(session.deadline_ns - now);
                    ignore Timer.setTimer<system>(#nanoseconds delay, func() : async () {
                        await handleDeadline(id);
                    });
                };
                case (_) {};
            };
        };
    };
};
