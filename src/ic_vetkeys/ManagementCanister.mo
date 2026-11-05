// This wrapper is vendored from the official Motoko `ic-vetkeys` package:
// https://github.com/dfinity/vetkeys/tree/main/backend/mo/ic_vetkeys
// It is kept local because Vessel package sets cannot address a package in a
// repository subdirectory.
// Upstream license: Apache-2.0.
import Blob "mo:core/Blob";
import Principal "mo:core/Principal";

module {
    public type VetKdKeyid = {
        curve : { #bls12_381_g2 };
        name : Text;
    };

    public type VetkdSystemApi = actor {
        vetkd_public_key : ({
            canister_id : ?Principal;
            context : Blob;
            key_id : VetKdKeyid;
        }) -> async ({ public_key : Blob });
        vetkd_derive_key : ({
            context : Blob;
            input : Blob;
            key_id : VetKdKeyid;
            transport_public_key : Blob;
        }) -> async ({ encrypted_key : Blob });
    };

    public func vetKdDeriveKey(
        input : Blob,
        context : Blob,
        keyId : VetKdKeyid,
        transportPublicKey : Blob,
    ) : async Blob {
        let request = {
            context;
            input;
            key_id = keyId;
            transport_public_key = transportPublicKey;
        };
        let (reply) = await (with cycles = 26_153_846_153)
            (actor ("aaaaa-aa") : VetkdSystemApi).vetkd_derive_key(request);
        reply.encrypted_key;
    };

    public func vetKdPublicKey(
        canisterId : ?Principal,
        context : Blob,
        keyId : VetKdKeyid,
    ) : async Blob {
        let request = {
            canister_id = canisterId;
            context;
            key_id = keyId;
        };
        let (reply) = await (actor ("aaaaa-aa") : VetkdSystemApi).vetkd_public_key(request);
        reply.public_key;
    };
};
