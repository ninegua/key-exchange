import Blob "mo:core/Blob";
import Nat "mo:core/Nat";
import Principal "mo:core/Principal";
import Result "mo:core/Result";
import Text "mo:core/Text";
import Crypto "./Crypto";
import Types "./Types";

module {
    public let IDENTITY_ABORT_ALICE = "fair_exchange_v1/abort/alice/b_X";
    public let IDENTITY_ABORT_BOB = "fair_exchange_v1/abort/bob/a_Y";
    public let IDENTITY_REVEAL_ALICE = "fair_exchange_v1/reveal/alice/b_Y";
    public let IDENTITY_REVEAL_BOB = "fair_exchange_v1/reveal/bob/a_X";

    public func newSession(
        id : Nat,
        alice : Principal,
        bob : Principal,
        now : Int,
        deadline_seconds : Nat,
    ) : Types.Session {
        {
            id;
            alice;
            bob;
            alice_commit = null;
            bob_commit = null;
            branch = #undecided;
            deadline_ns = now + Nat.toInt(deadline_seconds) * 1_000_000_000;
            alice_reveal_signal = false;
            bob_reveal_signal = false;
            alice_abort_signal = false;
            bob_abort_signal = false;
            alice_encrypted_key = null;
            bob_encrypted_key = null;
            closed = false;
        };
    };

    public func commitAs(
        session : Types.Session,
        caller : Principal,
        commit : Types.PartyCommit,
        now : Int,
    ) : Result.Result<Types.Session, Text> {
        switch (session.branch) {
            case (#undecided) {};
            case (_) { return #err("session already decided") };
        };
        if (now >= session.deadline_ns) {
            return #err("deadline passed");
        };

        let isAlice = Principal.equal(caller, session.alice);
        let isBob = Principal.equal(caller, session.bob);
        if (not isAlice and not isBob) {
            return #err("not a session participant");
        };

        if (isAlice) {
            switch (session.alice_commit) {
                case (?_) { return #err("Alice already committed") };
                case (null) {};
            };
        } else {
            switch (session.bob_commit) {
                case (?_) { return #err("Bob already committed") };
                case (null) {};
            };
        };

        switch (Crypto.validateCommit(commit, session.id)) {
            case (?err) { return #err(err) };
            case (null) {};
        };

        if (isAlice) {
            #ok({ session with alice_commit = ?commit });
        } else {
            #ok({ session with bob_commit = ?commit });
        };
    };

    public func signalAs(
        session : Types.Session,
        caller : Principal,
        signal : Types.Signal,
        now : Int,
    ) : Result.Result<Types.SignalOutcome, Text> {
        switch (session.branch) {
            case (#undecided) {};
            case (_) { return #err("branch already decided") };
        };

        let isAlice = Principal.equal(caller, session.alice);
        let isBob = Principal.equal(caller, session.bob);
        if (not isAlice and not isBob) {
            return #err("not a session participant");
        };

        if (now >= session.deadline_ns) {
            return #ok({
                session = { session with branch = #abort };
                decided = ?#abort;
            });
        };

        var updated = session;
        if (isAlice) {
            switch (signal) {
                case (#reveal) {
                    updated := { updated with alice_reveal_signal = true };
                };
                case (#abort) {
                    updated := { updated with alice_abort_signal = true };
                };
            };
        } else {
            switch (signal) {
                case (#reveal) {
                    updated := { updated with bob_reveal_signal = true };
                };
                case (#abort) {
                    updated := { updated with bob_abort_signal = true };
                };
            };
        };

        let decision : Types.Branch = switch (signal) {
            case (#abort) { #abort };
            case (#reveal) {
                if (updated.alice_reveal_signal and updated.bob_reveal_signal) {
                    #reveal;
                } else {
                    #undecided;
                };
            };
        };

        switch (decision) {
            case (#undecided) {
                #ok({ session = updated; decided = null });
            };
            case (branch) {
                #ok({
                    session = { updated with branch };
                    decided = ?branch;
                });
            };
        };
    };

    public func deadlineAbort(session : Types.Session, now : Int) : ?Types.Session {
        if (now < session.deadline_ns) {
            return null;
        };
        switch (session.branch) {
            case (#undecided) { ?{ session with branch = #abort } };
            case (_) { null };
        };
    };

    public func selectFinalization(session : Types.Session) : ?Types.Finalization {
        let (?alice) = session.alice_commit else return null;
        let (?bob) = session.bob_commit else return null;

        switch (session.branch) {
            case (#abort) {
                ?{
                    alice_identity = Text.encodeUtf8(IDENTITY_ABORT_ALICE);
                    alice_transport_pk = alice.transport_pk;
                    bob_identity = Text.encodeUtf8(IDENTITY_ABORT_BOB);
                    bob_transport_pk = bob.transport_pk;
                };
            };
            case (#reveal) {
                ?{
                    alice_identity = Text.encodeUtf8(IDENTITY_REVEAL_ALICE);
                    alice_transport_pk = alice.transport_pk;
                    bob_identity = Text.encodeUtf8(IDENTITY_REVEAL_BOB);
                    bob_transport_pk = bob.transport_pk;
                };
            };
            case (#undecided) { null };
        };
    };

    public func selectSharePackage(session : Types.Session, caller : Principal) : ?Types.SharePackage {
        let isAlice = Principal.equal(caller, session.alice);
        let isBob = Principal.equal(caller, session.bob);
        if (not isAlice and not isBob) { return null };

        switch (session.branch) {
            case (#abort) {
                if (isAlice) {
                    let (?bob) = session.bob_commit else return null;
                    let (?key) = session.alice_encrypted_key else return null;
                    ?{
                        encrypted_vetkey = key;
                        identity = Text.encodeUtf8(IDENTITY_ABORT_ALICE);
                        counterparty_ciphertext = bob.ciphertext_x;
                        counterparty_commitment = bob.commitment_x;
                        branch = #abort;
                    };
                } else {
                    let (?alice) = session.alice_commit else return null;
                    let (?key) = session.bob_encrypted_key else return null;
                    ?{
                        encrypted_vetkey = key;
                        identity = Text.encodeUtf8(IDENTITY_ABORT_BOB);
                        counterparty_ciphertext = alice.ciphertext_y;
                        counterparty_commitment = alice.commitment_y;
                        branch = #abort;
                    };
                };
            };
            case (#reveal) {
                if (isAlice) {
                    let (?bob) = session.bob_commit else return null;
                    let (?key) = session.alice_encrypted_key else return null;
                    ?{
                        encrypted_vetkey = key;
                        identity = Text.encodeUtf8(IDENTITY_REVEAL_ALICE);
                        counterparty_ciphertext = bob.ciphertext_y;
                        counterparty_commitment = bob.commitment_y;
                        branch = #reveal;
                    };
                } else {
                    let (?alice) = session.alice_commit else return null;
                    let (?key) = session.bob_encrypted_key else return null;
                    ?{
                        encrypted_vetkey = key;
                        identity = Text.encodeUtf8(IDENTITY_REVEAL_BOB);
                        counterparty_ciphertext = alice.ciphertext_x;
                        counterparty_commitment = alice.commitment_x;
                        branch = #reveal;
                    };
                };
            };
            case (#undecided) { null };
        };
    };
};
