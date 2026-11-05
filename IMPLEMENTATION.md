# Implementation guide

This document covers the concrete implementation: repository layout, Vessel
dependencies, `icp-cli` deployment, the Vite frontend, and tests. For the protocol
overview, math, and VetKeys design, see [README.md](README.md).

Run `make help` to list all available targets.

---

## 1. Repository layout

| Path | Purpose |
|---|---|
| `src/main.mo` | Motoko canister actor: sessions, timers, branch enforcement, VetKeys calls. |
| `src/State.mo` | Pure session state machine: commits, signals, deadlines, branch-specific identities, share-package selection. |
| `src/Crypto.mo` | BLS12-381 commitments, Schnorr proofs, commitment and share verification. |
| `src/Types.mo` | Candid-facing record, variant, and session types. |
| `src/ic_vetkeys/ManagementCanister.mo` | Local copy of the official `ic-vetkeys` management-canister wrapper. |
| `test/Unit.mo` | Motoko unit tests for crypto and state transitions. |
| `frontend/` | Vite single-page demo using mainnet Internet Identity. |
| `scripts/test.sh` | Compiles and runs the Motoko unit tests through WASI. |
| `scripts/test-local.sh` | Deploys the canister and checks `get_verification_key`. |
| `scripts/test-e2e.sh` | Full abort/reveal end-to-end test through the canister and VetKeys. |
| `icp.yaml` | `icp-cli` build, local network, test network, and environment configuration. |
| `Makefile` | Shortcuts for dependency installation, builds, deployment, and tests. |
| `key_exchange.did` | Generated Candid interface. |

The `ic-vetkeys` wrapper is vendored because Vessel package sets cannot address a
package in a repository subdirectory. It has no dependencies other than `core`.

---

## 2. Dependencies

Dependencies are managed by Vessel:

| Package | Version | Use |
|---|---|---|
| `core` | v2.6.1 | Motoko standard library. |
| `bls12-381` | v0.1.0 | G2 commitments and Schnorr proof verification. |
| `sha2` | 0.2.5 | SHA-256 for Schnorr challenges. |

`vessel.dhall`:

```dhall
{
  dependencies = [ "core", "bls12-381", "sha2" ],
  compiler = Some "1.15.0"
}
```

`package-set.dhall` contains the matching pins. Install all dependencies with:

```bash
make deps
```

This runs `vessel install` and installs the frontend npm packages. The generated
`.vessel/` directory is ignored by Git.

---

## 3. Build and deploy with `icp-cli`

The `build` target runs the Vessel and `moc` steps configured in `icp.yaml`:

```bash
make build
```

This produces `key_exchange.did` and the canister Wasm. `make build-all` also
builds the frontend, and `make build-frontend` builds only the Vite app.

### Test network used by the demo

```bash
make network-test
make deploy-test
```

The `test` network runs on port `18080`, avoiding collisions with the default
`local` network on port `8000`. Stop it with:

```bash
make network-stop
```

### Default local network

```bash
make network-local
make deploy-local
```

Stop it with `make network-stop-local`. No local Internet Identity canister is
created. The frontend always uses mainnet Internet Identity.

### Key name

`icp.yaml` sets:

```yaml
settings:
  environment_variables:
    VETKD_KEY_NAME: "test_key_1"
```

Use `test_key_1` locally and `key_1` on mainnet. Each session performs exactly two
`vetkd_derive_key` calls, roughly `5.3 × 10^10` cycles per session plus overhead.

### Candid

`key_exchange.did` is generated from the actor by `moc --idl`. The service
exposes:

- `create_session`
- `commit`
- `signal`
- `get_encrypted_share`
- `get_verification_key`
- `get_session`

---

## 4. Frontend demo

The demo is a single-page Vite application in `frontend/`.

### Stack

- `@icp-sdk/auth` for mainnet Internet Identity login.
- `@icp-sdk/core` for `HttpAgent`, `Principal`, and generated actor bindings.
- `@icp-sdk/vetkeys` for transport keys, VetKey decryption, and IBE.
- `@noble/curves` and `@noble/hashes` for client-side BLS12-381 commitments and
  Schnorr proofs.
- `@icp-sdk/bindgen` to generate actor bindings from `key_exchange.did`.

### Start the dev server

The canister must be deployed first. From the repository root:

```bash
make deps
make network-test
make deploy-test
make dev
```

`frontend/vite.config.js`:

- defaults `ICP_ENVIRONMENT` to `test`;
- reads the deployed canister ID and local root key from `icp`;
- injects them into the page via the `ic_env` cookie;
- proxies `/api` to the local network.

To use the default local network instead:

```bash
make network-local
make deploy-local
ICP_ENVIRONMENT=local make dev
```

Open the Vite URL on `http://localhost:...`, not `127.0.0.1`, when logging in with
mainnet Internet Identity.

### Login details

The auth client is configured with:

```js
agentOptions: { host: "https://icp-api.io" }
```

This is important when the app itself runs on localhost. The auth client mints
the session delegation by calling the **mainnet Internet Identity canister**.
Without the explicit host, its agent would inherit the local Vite origin and send
the II canister call through the local network proxy, where no II canister
exists. The app's own canister actor still uses the local root key and local
proxy.

The auth client also uses `windowOpenerFeatures` so Internet Identity opens in a
popup that keeps `window.opener` alive for the ICRC-29 postMessage channel.

### Two-party walkthrough

1. Open the Vite URL in browser A and log in with Internet Identity.
2. Open the same URL in browser B, or a private/containerised browser, and log in
   with a different Internet Identity principal.
3. In browser A, copy browser B's principal into “Bob's principal”, choose a
   deadline, and create the session. Browser A is Alice.
4. Copy the session ID to browser B and load it there. Browser B is Bob.
5. Both browsers click **Prepare & commit**.
6. Once both commitments are on-chain, either side may **Signal abort**, or both
   may **Signal reveal**.
7. After finalization, each browser fetches its branch-specific VetKey, decrypts
   the counterparty's IBE ciphertext, verifies the commitment, and displays the
   recovered private scalar and public key.

After both parties commit, the UI also computes and displays the committed public
keys:

- $\mathrm{pk}_X = A_X \cdot B_X$
- $\mathrm{pk}_Y = A_Y \cdot B_Y$

### Local state

The frontend keeps the transport secret key and the client's shares in memory for
the active session. Reloading the page after committing discards them; the
session can still be finalized by other participants, but that browser can no
longer decrypt its result. This is intentional for the demo.

---

## 5. Tests

### Unit tests

```bash
make test-unit
```

The script compiles `test/Unit.mo` with `moc -wasi-system-api` and runs it with
`wasmtime`. It covers:

- commitment opening and BLS12-381 composition;
- Schnorr proof generation and verification;
- commit authorization, duplicate prevention, deadline handling, and invalid
  proofs;
- abort/reveal branch transitions and irrevocability;
- branch-specific finalization identities;
- counterparty ciphertext and commitment selection for both parties.

### Local deployment smoke test

```bash
make test-local
```

Starts the `test` network, deploys the canister, calls
`get_verification_key`, and stops the network.

### Frontend/protocol end-to-end test

```bash
make test-e2e
```

Starts the local network, deploys the canister, creates two ephemeral identities,
commits with real BLS12-381 commitments and IBE ciphertexts, runs both the abort
and reveal branches, decrypts both sides' VetKeys, and checks the recovered
private keys and commitments.

### All tests

```bash
make test       # unit + end-to-end
make test-all   # unit + local smoke + end-to-end
```

### Frontend production build

```bash
make build-frontend
```

---

## 6. Operational notes

### Timers

Deadlines use `mo:core/Timer`. Timers are not persisted across upgrades, so
`postupgrade` re-arms pending deadlines for undecided sessions. The deadline
handler is idempotent.

### Debug logging

Finalization progress is logged from the canister:

```bash
make logs-test
```

The actor logs when each derivation starts and finishes, and when the session is
closed.

### Finalization

The canister starts both branch-derived `vetkd_derive_key` calls before awaiting
either one, so they are in flight concurrently. The session is marked `closed`
only after both encrypted VetKeys have been stored.

### Security note

The recipient checks every decrypted share against the corresponding on-chain
commitment. For production-grade abort fairness, the protocol should additionally
prove that each IBE ciphertext opens to the committed share, or include an
equivalent dispute/slashing mechanism. See the security section of
[README.md](README.md) for the details.
