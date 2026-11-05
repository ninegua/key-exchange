import Array "mo:core/Array";
import BLS "mo:bls12-381";
import Blob "mo:core/Blob";
import Nat "mo:core/Nat";
import Nat8 "mo:core/Nat8";
import Sha256 "mo:sha2/Sha256";
import Text "mo:core/Text";
import Types "./Types";

module {
    public let R : Nat = BLS.R_;

    // Fixed-width big-endian encoding used for scalars in proofs.
    public func natToBytes32(n : Nat) : Blob {
        Blob.fromArray(
            Array.tabulate<Nat8>(32, func(i : Nat) : Nat8 {
                let shift = 8 * (31 - i);
                Nat8.fromIntWrap(n / 2 ** shift);
            })
        );
    };

    public func decodeScalar(blob : Blob) : ?Nat {
        if (blob.size() != 32) { return null };
        ?BLS.decode_scalar(blob.toArray(), 0);
    };

    public func commitment(share : Nat) : Blob {
        Blob.fromArray(BLS.encode_g2(BLS.g2_mul(BLS.G2_GEN, share % R)));
    };

    public func verifyShare(commitmentBlob : Blob, share : Nat) : Bool {
        let (?point) = BLS.decode_g2(commitmentBlob.toArray(), 0) else return false;
        let expected = BLS.g2_mul(BLS.G2_GEN, share % R);
        BLS.encode_g2(point) == BLS.encode_g2(expected);
    };

    public func combineCommitments(a : Blob, b : Blob) : ?Blob {
        let (?pa) = BLS.decode_g2(a.toArray(), 0) else return null;
        let (?pb) = BLS.decode_g2(b.toArray(), 0) else return null;
        ?Blob.fromArray(BLS.encode_g2(BLS.g2_add(pa, pb)));
    };

    public func challenge(session_id : Nat, commitmentBlob : Blob, r : Blob) : Nat {
        let msg = Blob.fromArray(
            Array.flatten([
                Text.encodeUtf8("fair_exchange_v1/schnorr").toArray(),
                Text.encodeUtf8(Nat.toText(session_id)).toArray(),
                commitmentBlob.toArray(),
                r.toArray(),
            ])
        );
        BLS.decode_scalar(Sha256.fromBlob(#sha256, msg).toArray(), 0) % R;
    };

    // Used by clients and tests to create a Schnorr proof.
    public func proof(share : Nat, randomness : Nat, session_id : Nat) : Types.SchnorrProof {
        let rPoint = BLS.g2_mul(BLS.G2_GEN, randomness % R);
        let rBlob = Blob.fromArray(BLS.encode_g2(rPoint));
        let c = challenge(session_id, commitment(share), rBlob);
        let z = (randomness + c * (share % R)) % R;
        { r = rBlob; z = natToBytes32(z) };
    };

    public func verifySchnorr(
        commitmentBlob : Blob,
        proof : Types.SchnorrProof,
        session_id : Nat,
    ) : Bool {
        let (?cPoint) = BLS.decode_g2(commitmentBlob.toArray(), 0) else return false;
        let (?rPoint) = BLS.decode_g2(proof.r.toArray(), 0) else return false;
        let (?z) = decodeScalar(proof.z) else return false;
        if (z >= R) { return false };

        let c = challenge(session_id, commitmentBlob, proof.r);
        let lhs = BLS.g2_mul(BLS.G2_GEN, z);
        let rhs = BLS.g2_add(rPoint, BLS.g2_mul(cPoint, c));

        // bls12-381.mo v0.1.0 has no g2_eq; compare canonical encodings.
        BLS.encode_g2(lhs) == BLS.encode_g2(rhs);
    };

    public func validateCommit(commit : Types.PartyCommit, session_id : Nat) : ?Text {
        if (not verifySchnorr(commit.commitment_x, commit.proof_x, session_id)) {
            return ?"invalid proof for X commitment";
        };
        if (not verifySchnorr(commit.commitment_y, commit.proof_y, session_id)) {
            return ?"invalid proof for Y commitment";
        };
        null;
    };
};
