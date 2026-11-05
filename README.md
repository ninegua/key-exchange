# Branch-selecting TTP with VetKeys

A two-party key-exchange protocol running on the Internet Computer. It lets Alice
and Bob exchange two related private keys through one of two irrevocable
branches:

| Branch | Alice learns | Bob learns |
|---|---|---|
| **Abort** | $\mathit{sk}_X$ | $\mathit{sk}_Y$ |
| **Reveal** | $\mathit{sk}_Y$ | $\mathit{sk}_X$ |

Neither party can get both keys. The canister enforcing the branch is a
**branch-selecting TTP**. **TTP** stands for **trusted third party**: the entity
that a protocol relies on to hold secrets or enforce release. In a conventional
fair-exchange system, that third party would see the secrets. Here the canister
enforces the abort/reveal decision, but it is not trusted with the secrets
themselves: it sees only commitments and ciphertexts, and VetKeys releases the
missing share only through the chosen branch.

VetKeys is used to deliver that missing share as an encrypted, verifiable key
only after the branch is fixed.

Build, deployment, frontend, and test instructions are in
[IMPLEMENTATION.md](IMPLEMENTATION.md).

---

## 1. What problem does this solve?

Suppose Alice and Bob want to end up holding the two signing keys
$\mathit{sk}_X$ and $\mathit{sk}_Y$, corresponding to public keys $X$ and $Y$.
**Neither Alice nor Bob knows either signing key when the protocol starts.**
They are not exchanging pre-existing secrets: they first enter the protocol to
jointly create $X$ and $Y$ from fresh additive shares. Alice contributes one
share of each key and Bob contributes the other, so neither party can compute
either signing key on its own.

At the end of the protocol, the branch determines which signing key each party
learns: in the abort branch Alice learns $\mathit{sk}_X$ and Bob learns
$\mathit{sk}_Y$; in the reveal branch Alice learns $\mathit{sk}_Y$ and Bob
learns $\mathit{sk}_X$. Neither party ever learns both keys.

A normal trusted third party (TTP) could combine the shares and hand out the two
keys when a condition is met, but that requires the TTP to learn the keys.

This protocol keeps the TTP role—the canister decides which branch happens—but
removes the TTP's access to the secrets. The canister can enforce the branch
without ever holding a share or a private key. Concretely, it works as follows:

- each party contributes additive shares of both keys;
- each party encrypts its shares for the counterparty under branch-specific
  VetKeys identities;
- the canister records commitments, ciphertexts, signals, and a deadline;
- once the branch is irrevocably chosen, the canister asks the subnet for the
  VetKeys decryption keys for exactly that branch;
- each recipient uses its VetKey to decrypt the counterparty's share, verifies
  that the share matches the on-chain commitment, and reconstructs its private
  key locally.

The canister never receives a plaintext share. The subnet only returns VetKeys
encrypted under each recipient's transport public key. No node, no subnet, and
no canister ever sees a plaintext share or private key.

The branch is chosen as follows:

- **Abort** if either party signals abort, or if the deadline expires before both
  parties have revealed.
- **Reveal** only if both parties signal reveal before the deadline.

Once chosen, the branch cannot be changed. That is what makes the release
irrevocable.

---

## 2. Protocol at a glance

### Phase 1 — Setup and commitments

Alice chooses random shares $a_X, a_Y$; Bob chooses random shares $b_X, b_Y$
in the scalar field of BLS12-381.

Each party publishes:

- a transport public key for receiving encrypted VetKeys;
- commitments $A_X = g^{a_X}$, $A_Y = g^{a_Y}$ for Alice and
  $B_X = g^{b_X}$, $B_Y = g^{b_Y}$ for Bob;
- Schnorr proofs that it knows the committed shares;
- IBE ciphertexts of its shares, encrypted for the branch and recipient in which
  the counterparty is allowed to receive that share.

### Phase 2 — Branch decision

The canister enforces the state machine:

- any abort signal immediately selects `abort`;
- two reveal signals select `reveal`;
- the deadline selects `abort` if the session is still undecided.

This decision is final. Further commits or signals are rejected.

### Phase 3 — Branch-specific release

The canister calls `vetkd_derive_key` exactly twice, for the two recipients and
the two branch-specific identities of the chosen branch.

#### Abort branch

| Recipient | Identity | Share decrypted locally | Key reconstructed |
|---|---|---|---|
| Alice | `abort/alice/b_X` | Bob's $b_X$ | $\mathit{sk}_X = a_X + b_X$ |
| Bob | `abort/bob/a_Y` | Alice's $a_Y$ | $\mathit{sk}_Y = a_Y + b_Y$ |

#### Reveal branch

| Recipient | Identity | Share decrypted locally | Key reconstructed |
|---|---|---|---|
| Alice | `reveal/alice/b_Y` | Bob's $b_Y$ | $\mathit{sk}_Y = a_Y + b_Y$ |
| Bob | `reveal/bob/a_X` | Alice's $a_X$ | $\mathit{sk}_X = a_X + b_X$ |

The canister never derives the identities of the branch that was not selected.

---

## 3. Mathematical model

Let $G$ be the BLS12-381 G2 group of prime order $r$, with generator $g$.
Shares and private keys are scalars modulo $r$.

### Shares and public keys

Alice contributes

$$
a_X, a_Y \in \mathbb{Z}_r
$$

Bob contributes

$$
b_X, b_Y \in \mathbb{Z}_r
$$

The two private keys are the sums of the parties' shares:

$$
\mathit{sk}_X = a_X + b_X \bmod r
$$

$$
\mathit{sk}_Y = a_Y + b_Y \bmod r
$$

The corresponding public keys are:

$$
X = g^{\mathit{sk}_X}
  = g^{a_X + b_X}
  = A_X \cdot B_X
$$

$$
Y = g^{\mathit{sk}_Y}
  = g^{a_Y + b_Y}
  = A_Y \cdot B_Y
$$

where the commitments are:

$$
A_X = g^{a_X}, \quad A_Y = g^{a_Y}, \quad
B_X = g^{b_X}, \quad B_Y = g^{b_Y}
$$

Neither party can compute $\mathit{sk}_X$ or $\mathit{sk}_Y$ from the public
commitments alone, and neither party knows the other side's shares before the
branch is finalized.

### Schnorr proofs

A commitment alone does not prove that a party knows its discrete logarithm.
During commit, each party provides a Schnorr proof for each share:

- prover knows $s$ such that $C = g^s$;
- chooses nonce $k$, computes $R = g^k$;
- challenge $c = H(\mathit{session\_id} \Vert C \Vert R)$;
- response $z = k + c \cdot s \bmod r$.

The canister verifies

$$
g^z = R \cdot C^c
$$

This proves knowledge of the share behind each commitment without revealing it.

After decryption, a recipient also checks that the recovered share matches the
counterparty's on-chain commitment:

$$
g^s = C
$$

and finally checks the reconstructed public key:

$$
g^{\mathit{sk}_X} = A_X \cdot B_X
$$

or

$$
g^{\mathit{sk}_Y} = A_Y \cdot B_Y
$$

depending on the branch and role.

### Why additive shares?

The additive structure lets each private key remain split between the two
parties until the branch is fixed. The canister only stores group elements and
ciphertexts, so it cannot combine the shares itself. The final addition happens
locally in each recipient's browser.

---

## 4. How VetKeys is used

VetKeys provides **verifiably encrypted threshold key derivation**. For this
protocol it is used as an identity-based-encryption (IBE) key release service:

1. The canister has a fixed VetKeys context, `fair_exchange_v1`.
2. The clients fetch the context public key with `vetkd_public_key`.
3. Each client encrypts its shares using `IbeCiphertext.encrypt` for a specific
   identity:
   - Alice's $a_X$ for `reveal/bob/a_X`;
   - Alice's $a_Y$ for `abort/bob/a_Y`;
   - Bob's $b_X$ for `abort/alice/b_X`;
   - Bob's $b_Y$ for `reveal/alice/b_Y`.
4. The canister stores only the resulting ciphertexts.
5. When the branch is fixed, the canister calls `vetkd_derive_key` with the
   identity of each recipient's entitled share and the recipient's transport
   public key.
6. The subnet returns a **VetKey** encrypted under the recipient's transport
   key. The canister cannot decrypt it.
7. The recipient decrypts the VetKey locally, uses it to decrypt the
   counterparty's IBE ciphertext, verifies the recovered share against the
   commitment, and adds it to its own share.

The four identities are deliberately disjoint:

- `fair_exchange_v1/abort/alice/b_X`
- `fair_exchange_v1/abort/bob/a_Y`
- `fair_exchange_v1/reveal/alice/b_Y`
- `fair_exchange_v1/reveal/bob/a_X`

Only the identities selected by the branch are ever derived by the canister.
Because VetKeys threshold derivation returns an encrypted key rather than a
plaintext scalar, the canister and the subnet never learn the share or the final
private key.

### What each side receives

In the **abort** branch:

- Alice gets the VetKey for `abort/alice/b_X`, decrypts Bob's $b_X$, and
  reconstructs $\mathit{sk}_X$.
- Bob gets the VetKey for `abort/bob/a_Y`, decrypts Alice's $a_Y$, and
  reconstructs $\mathit{sk}_Y$.

In the **reveal** branch:

- Alice gets the VetKey for `reveal/alice/b_Y`, decrypts Bob's $b_Y$, and
  reconstructs $\mathit{sk}_Y$.
- Bob gets the VetKey for `reveal/bob/a_X`, decrypts Alice's $a_X$, and
  reconstructs $\mathit{sk}_X$.

Neither party ever receives both counterparty shares for the same key.

---

## 5. Security properties

### Confidentiality

The canister stores commitments, IBE ciphertexts, transport public keys, and
proofs. It never stores or derives a plaintext share. VetKeys decrypts only to
the recipient's transport key, so the canister and subnet see ciphertext.

### Irrevocable branch selection

The canister state machine rejects signals after a branch is fixed. Finalization
derives only the identities belonging to that branch. There is no code path that
releases both the abort-branch and reveal-branch shares for the same session.

### Fairness

If both parties submitted valid ciphertexts, the abort branch gives each party
exactly the share it is entitled to, and the reveal branch requires both parties
to reveal. The commitment checks detect a counterparty that tries to substitute a
different share.

### Remaining assumptions

- The canister code must be correct and immutable, or governed by a DAO.
- VetKeys threshold security assumes an honest quorum of subnet nodes.
- Clients must verify decrypted shares against commitments and verify the
  reconstructed public key.
- A production implementation should also prove that each IBE ciphertext opens
  to the committed share (verifiable encryption), or add an equivalent
  dispute/slashing mechanism. Without that proof, a malicious party could upload
  a malformed ciphertext before aborting. The recipient-side commitment check is
  necessary but not sufficient to prevent that griefing case.
