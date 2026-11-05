import Blob "mo:core/Blob";
import Principal "mo:core/Principal";

module {
    public type SchnorrProof = {
        r : Blob; // uncompressed BLS12-381 G2 point
        z : Blob; // 32-byte big-endian scalar
    };

    public type PartyCommit = {
        transport_pk : Blob;
        commitment_x : Blob;
        commitment_y : Blob;
        proof_x : SchnorrProof;
        proof_y : SchnorrProof;
        ciphertext_x : Blob;
        ciphertext_y : Blob;
    };

    public type Branch = {
        #undecided;
        #abort;
        #reveal;
    };

    public type Signal = {
        #reveal;
        #abort;
    };

    public type Session = {
        id : Nat;
        alice : Principal;
        bob : Principal;
        alice_commit : ?PartyCommit;
        bob_commit : ?PartyCommit;
        branch : Branch;
        deadline_ns : Int;
        alice_reveal_signal : Bool;
        bob_reveal_signal : Bool;
        alice_abort_signal : Bool;
        bob_abort_signal : Bool;
        alice_encrypted_key : ?Blob;
        bob_encrypted_key : ?Blob;
        closed : Bool;
    };

    public type SharePackage = {
        encrypted_vetkey : Blob;
        identity : Blob;
        counterparty_ciphertext : Blob;
        counterparty_commitment : Blob;
        branch : Branch;
    };

    public type Finalization = {
        alice_identity : Blob;
        alice_transport_pk : Blob;
        bob_identity : Blob;
        bob_transport_pk : Blob;
    };

    public type SignalOutcome = {
        session : Session;
        decided : ?Branch;
    };
};
