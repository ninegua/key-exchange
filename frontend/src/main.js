import "./style.css";

import { AuthClient } from "@icp-sdk/auth/client";
import { HttpAgent } from "@icp-sdk/core/agent";
import { safeGetCanisterEnv } from "@icp-sdk/core/agent/canister-env";
import { Principal } from "@icp-sdk/core/principal";
import {
  DerivedPublicKey,
  EncryptedVetKey,
  IbeCiphertext,
  IbeIdentity,
  IbeSeed,
  TransportSecretKey,
} from "@icp-sdk/vetkeys";

import { createActor, Branch, Signal } from "./bindings/key_exchange";
import {
  IDENTITY,
  addShares,
  bigIntToBytes32,
  bytesToBigInt,
  bytesToHex,
  commitmentFor,
  combineCommitmentBytes,
  publicKeyFor,
  randomScalar,
  schnorrProof,
  verifyCommitment,
} from "./protocol";

const CANISTER_NAME = "key_exchange";
const canisterEnv = safeGetCanisterEnv();
const canisterId =
  canisterEnv?.[`PUBLIC_CANISTER_ID:${CANISTER_NAME}`] ??
  import.meta.env.VITE_CANISTER_ID;
const rootKey = canisterEnv?.IC_ROOT_KEY;
const explicitHost = canisterEnv ? undefined : import.meta.env.VITE_IC_HOST;

const state = {
  authClient: null,
  identity: null,
  principal: null,
  actor: null,
  dpk: null,
  dpkBytes: null,
  sessionId: null,
  session: null,
  role: null,
  tsk: null,
  shares: null,
  result: null,
  pollTimer: null,
  refreshing: false,
  busy: false,
  logs: [],
};

const $ = (id) => document.getElementById(id);
const now = () => new Date().toLocaleTimeString();

function setStatus(message, isError = false) {
  const el = $("action-status");
  if (!el) return;
  el.textContent = message;
  el.classList.toggle("error", isError);
}

function setLoginStatus(message, isError = false) {
  const el = $("login-status");
  if (!el) return;
  el.textContent = message;
  el.classList.toggle("error", isError);
}

function log(message, kind = "info") {
  state.logs.push({ time: now(), message, kind });
  if (state.logs.length > 40) state.logs.shift();
  renderLog();
}

function renderLog() {
  const list = $("log");
  if (!list) return;
  list.replaceChildren(
    ...state.logs.map((entry) => {
      const li = document.createElement("li");
      li.className = `log-${entry.kind}`;
      const time = document.createElement("span");
      time.className = "log-time";
      time.textContent = entry.time;
      const text = document.createElement("span");
      text.textContent = entry.message;
      li.append(time, text);
      return li;
    }),
  );
}

function principalText(value) {
  return value ? value.toText() : "—";
}

function branchLabel(branch) {
  if (branch === Branch.abort) return "abort";
  if (branch === Branch.reveal) return "reveal";
  return "undecided";
}

function shortHex(bytes, head = 12, tail = 8) {
  const hex = bytesToHex(bytes);
  if (hex.length <= head + tail + 3) return hex;
  return `${hex.slice(0, head)}…${hex.slice(-tail)}`;
}

function setHidden(id, hidden) {
  const el = $(id);
  if (el) el.classList.toggle("hidden", hidden);
}

function setDisabled(id, disabled) {
  const el = $(id);
  if (el) el.disabled = disabled;
}

function showApp() {
  $("login-panel").classList.add("hidden");
  $("app").classList.remove("hidden");
  $("principal").textContent = state.principal
    ? `Logged in as ${state.principal.toText()}`
    : "";
  setHidden("login-btn", Boolean(state.principal));
  setHidden("logout-btn", !state.principal);
}

function showLogin() {
  $("login-panel").classList.remove("hidden");
  $("app").classList.add("hidden");
  $("principal").textContent = "Not logged in";
  setHidden("login-btn", false);
  setHidden("logout-btn", true);
}

async function initAuth() {
  if (!canisterId) {
    const message =
      "Canister ID is not configured. Start the Vite dev server via `npm run dev` (it injects the deployed canister ID), or set VITE_CANISTER_ID.";
    setStatus(message, true);
    setLoginStatus(message, true);
    return;
  }

  // Mainnet Internet Identity. No local II canister is required.
  state.authClient = new AuthClient({
    // Use a real popup (rather than a new tab) so the II window keeps
    // `window.opener` and can deliver the sign-in result via postMessage.
    windowOpenerFeatures:
      "toolbar=0,location=0,menubar=0,width=520,height=680,left=120,top=80",
    // The auth client mints the delegation by calling the mainnet Internet
    // Identity canister. Do not let its agent inherit the local Vite origin:
    // on localhost that would send the II canister call through the local
    // network proxy, where no II canister exists. The app's own actor still
    // uses the local root key and the local proxy.
    agentOptions: { host: "https://icp-api.io" },
  });

  if (state.authClient.isAuthenticated()) {
    state.identity = await state.authClient.getIdentity();
    state.principal = state.identity.getPrincipal();
    showApp();
    log(`Logged in as ${state.principal.toText()}`, "good");
    try {
      await ensureActor();
      startPolling();
    } catch (error) {
      console.error("[auth] actor creation failed", error);
      setStatus(`Connected, but could not create the canister actor: ${error.message ?? error}`, true);
    }
  } else {
    showLogin();
  }
}

async function login() {
  try {
    setLoginStatus("Opening Internet Identity in a popup…");
    setStatus("Opening Internet Identity…");
    console.log("[auth] signIn started", {
      origin: window.location.origin,
      userAgent: navigator.userAgent,
    });
    const identity = await state.authClient.signIn({
      maxTimeToLive: BigInt(30 * 60) * BigInt(1_000_000_000),
    });
    console.log(
      "[auth] signIn resolved",
      identity.getPrincipal().toText(),
    );
    state.identity = identity;
    state.principal = identity.getPrincipal();
    // Show the logged-in state immediately. Actor construction is separate so
    // a network/configuration problem does not look like a failed login.
    showApp();
    setLoginStatus("");
    log(`Logged in as ${state.principal.toText()}`, "good");
    setStatus("Logged in. Create or load a session.");
    try {
      await ensureActor();
      startPolling();
    } catch (error) {
      console.error("[auth] actor creation failed", error);
      setStatus(`Logged in, but could not create the canister actor: ${error.message ?? error}`, true);
    }
  } catch (error) {
    console.error("[auth] signIn failed", error);
    setLoginStatus(`Login failed: ${error.message ?? error}`, true);
    setStatus(`Login failed: ${error.message ?? error}`, true);
  }
}

async function logout() {
  await state.authClient?.signOut();
  stopPolling();
  state.identity = null;
  state.principal = null;
  state.actor = null;
  state.sessionId = null;
  state.session = null;
  state.role = null;
  state.tsk = null;
  state.shares = null;
  state.result = null;
  state.dpk = null;
  state.dpkBytes = null;
  setLoginStatus("");
  showLogin();
  render();
}

async function ensureActor() {
  if (state.actor) return state.actor;
  const agent = await HttpAgent.create({
    identity: state.identity,
    rootKey,
    host: explicitHost,
  });
  state.actor = createActor(canisterId, { agent });
  return state.actor;
}

async function ensureVerificationKey() {
  if (state.dpk) return state.dpk;
  const actor = await ensureActor();
  const bytes = await actor.get_verification_key();
  state.dpkBytes = Uint8Array.from(bytes);
  state.dpk = DerivedPublicKey.deserialize(state.dpkBytes);
  log("Fetched VetKeys context verification key.", "info");
  return state.dpk;
}

function startPolling() {
  if (state.pollTimer) return;
  state.pollTimer = setInterval(() => {
    void refreshSession();
  }, 2500);
}

function stopPolling() {
  if (state.pollTimer) {
    clearInterval(state.pollTimer);
    state.pollTimer = null;
  }
}

function resetLocalCryptoForNewSession(sessionId) {
  if (state.sessionId === sessionId) return;
  state.sessionId = sessionId;
  state.needsFreshLocalData = true;
  state.tsk = null;
  state.shares = null;
  state.result = null;
}

async function createSession() {
  if (state.busy) return;
  try {
    state.busy = true;
    const actor = await ensureActor();
    const counterpartyText = $("counterparty").value.trim();
    if (!counterpartyText) throw new Error("Enter the counterparty principal.");
    const counterparty = Principal.fromText(counterpartyText);
    if (counterparty.toText() === state.principal.toText()) {
      throw new Error("Counterparty must be a different principal.");
    }
    const seconds = Number.parseInt($("deadline").value, 10);
    if (!Number.isFinite(seconds) || seconds < 10) {
      throw new Error("Deadline must be at least 10 seconds.");
    }
    setStatus("Creating session…");
    const id = await actor.create_session(counterparty, BigInt(seconds));
    log(`Created session ${id}.`, "good");
    $("session-id").value = id.toString();
    await loadSession(id);
  } catch (error) {
    setStatus(error.message ?? String(error), true);
  } finally {
    state.busy = false;
    render();
  }
}

async function loadSession(sessionIdInput) {
  try {
    state.busy = true;
    const sessionId =
      typeof sessionIdInput === "bigint"
        ? sessionIdInput
        : BigInt(String(sessionIdInput).trim());
    const actor = await ensureActor();
    const session = await actor.get_session(sessionId);
    if (!session) throw new Error(`Session ${sessionId} does not exist.`);
    resetLocalCryptoForNewSession(sessionId);
    state.session = session;
    state.role = null;
    if (session.alice.toText() === state.principal.toText()) {
      state.role = "alice";
    } else if (session.bob.toText() === state.principal.toText()) {
      state.role = "bob";
    } else {
      throw new Error(
        "This session is not addressed to the logged-in principal. Create a new session or login as a participant.",
      );
    }
    $("session-id").value = sessionId.toString();
    await ensureVerificationKey();
    log(
      `Loaded session ${sessionId} as ${state.role === "alice" ? "Alice" : "Bob"}.`,
      "good",
    );
    startPolling();
    setStatus("Session loaded. Review the status and commit when ready.");
    render();
  } catch (error) {
    setStatus(error.message ?? String(error), true);
  } finally {
    state.busy = false;
    render();
  }
}

async function refreshSession() {
  if (!state.actor || !state.sessionId || state.refreshing) return;
  state.refreshing = true;
  try {
    const session = await state.actor.get_session(state.sessionId);
    if (session) {
      state.session = session;
      render();
      if (session.closed && !state.result && state.tsk && state.shares) {
        await fetchResult();
      }
    }
  } catch (error) {
    log(`Refresh failed: ${error.message ?? error}`, "error");
  } finally {
    state.refreshing = false;
  }
}

function myCommit() {
  if (!state.session || !state.role) return undefined;
  return state.role === "alice"
    ? state.session.alice_commit
    : state.session.bob_commit;
}

function bothCommitted() {
  return Boolean(state.session?.alice_commit && state.session?.bob_commit);
}

function ensureLocalSecrets() {
  if (!state.tsk) {
    state.tsk = TransportSecretKey.random();
  }
  if (!state.shares) {
    state.shares = {
      x: randomScalar(),
      y: randomScalar(),
    };
  }
}

function identityFor(role, axis) {
  if (role === "alice") {
    return axis === "x" ? IDENTITY.revealBob : IDENTITY.abortBob;
  }
  return axis === "x" ? IDENTITY.abortAlice : IDENTITY.revealAlice;
}

async function prepareAndCommit() {
  if (state.busy || !state.session || !state.role) return;
  if (state.session.branch !== Branch.undecided) {
    setStatus("The branch is already decided.", true);
    return;
  }
  if (myCommit()) {
    setStatus("You have already committed.", true);
    return;
  }

  try {
    state.busy = true;
    setStatus("Preparing shares, commitments, proofs, and IBE ciphertexts…");
    await ensureVerificationKey();
    ensureLocalSecrets();
    const dpk = state.dpk;
    const { x: shareX, y: shareY } = state.shares;
    const commitmentX = commitmentFor(shareX);
    const commitmentY = commitmentFor(shareY);
    const proofX = schnorrProof(shareX, randomScalar(), state.sessionId);
    const proofY = schnorrProof(shareY, randomScalar(), state.sessionId);
    const ciphertextX = IbeCiphertext.encrypt(
      dpk,
      IbeIdentity.fromString(identityFor(state.role, "x")),
      bigIntToBytes32(shareX),
      IbeSeed.random(),
    ).serialize();
    const ciphertextY = IbeCiphertext.encrypt(
      dpk,
      IbeIdentity.fromString(identityFor(state.role, "y")),
      bigIntToBytes32(shareY),
      IbeSeed.random(),
    ).serialize();

    const result = await state.actor.commit(
      state.sessionId,
      state.tsk.publicKeyBytes(),
      commitmentX,
      commitmentY,
      proofX,
      proofY,
      ciphertextX,
      ciphertextY,
    );

    if (result.__kind__ === "err") {
      throw new Error(result.err);
    }

    log("Commitment accepted by the canister.", "good");
    setStatus("Committed. Waiting for the counterparty.");
    await refreshSession();
  } catch (error) {
    setStatus(`Commit failed: ${error.message ?? error}`, true);
    log(`Commit failed: ${error.message ?? error}`, "error");
  } finally {
    state.busy = false;
    render();
  }
}

async function sendSignal(signal) {
  if (state.busy || !state.session || !state.role) return;
  if (!myCommit()) {
    setStatus("Commit before signaling.", true);
    return;
  }
  if (!bothCommitted()) {
    setStatus("Both parties must commit before signaling.", true);
    return;
  }
  if (state.session.branch !== Branch.undecided) {
    setStatus("The branch is already decided.", true);
    return;
  }

  try {
    state.busy = true;
    setStatus(`Sending ${signal} signal…`);
    const result = await state.actor.signal(state.sessionId, signal);
    if (result.__kind__ === "err") {
      throw new Error(result.err);
    }
    log(`Sent ${signal} signal.`, "info");
    await refreshSession();
    if (state.session?.branch === Branch.undecided) {
      setStatus("Signal recorded. Waiting for the counterparty.");
    } else {
      setStatus(`Branch decided: ${branchLabel(state.session.branch)}. Waiting for finalization…`);
    }
  } catch (error) {
    setStatus(`Signal failed: ${error.message ?? error}`, true);
    log(`Signal failed: ${error.message ?? error}`, "error");
  } finally {
    state.busy = false;
    render();
  }
}

async function fetchResult() {
  if (!state.session?.closed || state.result) return;
  if (!state.tsk || !state.shares) {
    log(
      "This browser no longer has the local transport key/shares for this session. Commit from this browser before the branch is decided.",
      "error",
    );
    return;
  }

  try {
    const result = await state.actor.get_encrypted_share(state.sessionId);
    if (result.__kind__ === "err") {
      throw new Error(result.err);
    }
    const pkg = result.ok;
    const vetKey = EncryptedVetKey.deserialize(pkg.encrypted_vetkey).decryptAndVerify(
      state.tsk,
      state.dpk,
      pkg.identity,
    );
    const counterpartyShareBytes = IbeCiphertext.deserialize(
      pkg.counterparty_ciphertext,
    ).decrypt(vetKey);
    const counterpartyShare = bytesToBigInt(counterpartyShareBytes);

    if (!verifyCommitment(pkg.counterparty_commitment, counterpartyShare)) {
      throw new Error("Counterparty share does not match its on-chain commitment.");
    }

    let ownShare;
    let keyName;
    if (state.role === "alice") {
      ownShare = pkg.branch === Branch.abort ? state.shares.x : state.shares.y;
      keyName = pkg.branch === Branch.abort ? "sk_X" : "sk_Y";
    } else {
      ownShare = pkg.branch === Branch.abort ? state.shares.y : state.shares.x;
      keyName = pkg.branch === Branch.abort ? "sk_Y" : "sk_X";
    }

    const secret = addShares(ownShare, counterpartyShare);
    const publicKey = publicKeyFor(secret);
    state.result = {
      branch: pkg.branch,
      role: state.role,
      keyName,
      counterpartyShare: bytesToHex(counterpartyShareBytes),
      secret: bytesToHex(bigIntToBytes32(secret)),
      publicKey: bytesToHex(publicKey),
      verified: true,
    };
    log(
      `${state.role === "alice" ? "Alice" : "Bob"} recovered ${keyName} and verified the counterparty share.`,
      "good",
    );
    setStatus(`Complete. Derived ${keyName}.`);
    render();
  } catch (error) {
    log(`Result fetch failed: ${error.message ?? error}`, "error");
    setStatus(`Result fetch failed: ${error.message ?? error}`, true);
  }
}

function renderParty(role) {
  const isYou = state.role === role;
  const card = $(`${role}-card`);
  if (!card) return;
  card.classList.toggle("you", isYou);
  $(`${role}-you`).classList.toggle("hidden", !isYou);
  const session = state.session;
  const commit = session?.[`${role}_commit`];
  $(`${role}-principal`).textContent = principalText(session?.[role]);
  $(`${role}-commit-status`).textContent = commit
    ? `committed (${shortHex(commit.commitment_x)} / ${shortHex(commit.commitment_y)})`
    : "not committed";
  $(`${role}-commit-dot`).className = `dot ${commit ? "on" : ""}`;

  const reveal = Boolean(session?.[`${role}_reveal_signal`]);
  const abort = Boolean(session?.[`${role}_abort_signal`]);
  $(`${role}-signal-status`).textContent = `reveal: ${reveal ? "yes" : "no"} · abort: ${abort ? "yes" : "no"}`;
  $(`${role}-signal-dot`).className = `dot ${reveal || abort ? "on" : ""}`;
}

function render() {
  if (!state.principal) return;
  const session = state.session;
  const hasSession = Boolean(session);
  $("session-meta").textContent = hasSession
    ? `Session #${session.id} · branch: ${branchLabel(session.branch)} · deadline: ${new Date(Number(session.deadline_ns / 1_000_000n)).toLocaleString()}`
    : "No session loaded.";
  $("session-panel").classList.toggle("hidden", !hasSession);
  $("action-panel").classList.toggle("hidden", !hasSession);

  renderParty("alice");
  renderParty("bob");

  if (!hasSession) {
    setDisabled("prepare-btn", true);
    setDisabled("reveal-btn", true);
    setDisabled("abort-btn", true);
    $("turn-hint").textContent = "Create a session as Alice, or load an existing session as Bob.";
    setHidden("result-card", true);
    return;
  }

  const committed = Boolean(myCommit());
  const both = bothCommitted();
  const undecided = session.branch === Branch.undecided;
  const roleLabel = state.role === "alice" ? "Alice" : "Bob";
  const otherLabel = state.role === "alice" ? "Bob" : "Alice";

  setDisabled("prepare-btn", committed || !undecided || state.busy);
  setDisabled("reveal-btn", !committed || !both || !undecided || state.busy);
  setDisabled("abort-btn", !committed || !both || !undecided || state.busy);

  if (!committed) {
    $("turn-hint").textContent = `You are ${roleLabel}. Prepare your shares and commit them. ${otherLabel} must do the same in another browser.`;
  } else if (!both) {
    $("turn-hint").textContent = `${roleLabel} has committed. Waiting for ${otherLabel} to commit from their browser.`;
  } else if (undecided) {
    $("turn-hint").textContent = `Both parties committed. Choose “reveal” to release the crossed keys, or “abort” to release the abort-branch keys.`;
  } else if (!session.closed) {
    $("turn-hint").textContent = `Branch ${branchLabel(session.branch)} is fixed. Waiting for the canister to derive the encrypted VetKeys…`;
  } else {
    $("turn-hint").textContent = `Branch ${branchLabel(session.branch)} finalized. Your result is below.`;
  }

  renderPublicKeys();
  renderResult();
}

function renderPublicKeys() {
  const card = $("public-keys-card");
  if (!card) return;
  const session = state.session;
  if (!session) {
    card.classList.add("hidden");
    return;
  }
  card.classList.remove("hidden");
  if (!session.alice_commit || !session.bob_commit) {
    $("pk-x").textContent = "Waiting for both commitments…";
    $("pk-y").textContent = "Waiting for both commitments…";
    return;
  }

  try {
    const pkX = combineCommitmentBytes(
      session.alice_commit.commitment_x,
      session.bob_commit.commitment_x,
    );
    const pkY = combineCommitmentBytes(
      session.alice_commit.commitment_y,
      session.bob_commit.commitment_y,
    );
    $("pk-x").textContent = bytesToHex(pkX);
    $("pk-y").textContent = bytesToHex(pkY);
  } catch (error) {
    $("pk-x").textContent = `Could not compute: ${error.message ?? error}`;
    $("pk-y").textContent = `Could not compute: ${error.message ?? error}`;
  }
}

function renderResult() {
  const card = $("result-card");
  const result = state.result;
  if (!result) {
    card.classList.add("hidden");
    return;
  }
  card.classList.remove("hidden");
  $("result-title").textContent = `${result.role === "alice" ? "Alice" : "Bob"} obtained ${result.keyName}`;
  $("result-branch").textContent = branchLabel(result.branch);
  $("result-share").textContent = result.counterpartyShare;
  $("result-secret").textContent = result.secret;
  $("result-public").textContent = result.publicKey;
  $("result-verified").textContent = result.verified
    ? "Yes — recovered share matches the counterparty commitment."
    : "No";
}

function setupDom() {
  $("root").innerHTML = `
    <div class="layout">
      <section class="card intro-card">
        <div class="eyebrow">VetKeys fair exchange</div>
        <h1>Commit. Reveal or abort.</h1>
        <p class="lede">
          Two parties commit to additive shares, then the branch decides which crossed
          key each side may recover. The canister never sees a plaintext share:
          VetKeys IBE delivers the counterparty's share only through the chosen branch.
        </p>
        <div class="auth-row">
          <span id="principal" class="principal-pill">Not logged in</span>
          <button id="login-btn" class="primary">Login with Internet Identity</button>
          <button id="logout-btn" class="ghost hidden">Logout</button>
        </div>
        <p class="hint">
          Open this page in a second browser or container and log in with a different
          Internet Identity principal to act as the other party.
        </p>
      </section>

      <section id="login-panel" class="card login-card">
        <h2>Login required</h2>
        <p class="hint">Use mainnet Internet Identity (https://id.ai). No local II canister is used.</p>
        <p id="login-status" class="status"></p>
      </section>

      <div id="app" class="hidden">
        <section class="card">
          <div class="section-head">
            <div>
              <div class="eyebrow">Session setup</div>
              <h2>Create or join</h2>
            </div>
            <span class="pill">One identity per browser</span>
          </div>
          <div class="setup-grid">
            <div class="setup-box">
              <h3>Create as Alice</h3>
              <label for="counterparty">Bob's principal</label>
              <input id="counterparty" placeholder="Paste the other browser's principal" />
              <label for="deadline">Deadline (seconds)</label>
              <input id="deadline" type="number" min="10" value="300" />
              <button id="create-btn" class="primary">Create session</button>
            </div>
            <div class="setup-box">
              <h3>Join as Bob</h3>
              <label for="session-id">Session ID</label>
              <input id="session-id" placeholder="Ask Alice for the session ID" />
              <button id="load-btn" class="secondary">Load session</button>
              <p class="hint">Bob loads the session after Alice creates it with Bob's principal.</p>
            </div>
          </div>
          <p id="session-meta" class="session-meta">No session loaded.</p>
        </section>

        <section id="session-panel" class="hidden">
          <div class="party-grid">
            <article id="alice-card" class="card party-card">
              <div class="party-head">
                <div>
                  <div class="eyebrow">Party</div>
                  <h2>Alice <span id="alice-you" class="you-badge hidden">you</span></h2>
                </div>
                <span id="alice-commit-dot" class="dot"></span>
              </div>
              <p id="alice-principal" class="principal-line">—</p>
              <p class="status-line"><span id="alice-signal-dot" class="dot"></span><span id="alice-commit-status">not committed</span></p>
              <p class="status-line subtle"><span id="alice-signal-status">reveal: no · abort: no</span></p>
            </article>
            <article id="bob-card" class="card party-card">
              <div class="party-head">
                <div>
                  <div class="eyebrow">Party</div>
                  <h2>Bob <span id="bob-you" class="you-badge hidden">you</span></h2>
                </div>
                <span id="bob-commit-dot" class="dot"></span>
              </div>
              <p id="bob-principal" class="principal-line">—</p>
              <p class="status-line"><span id="bob-signal-dot" class="dot"></span><span id="bob-commit-status">not committed</span></p>
              <p class="status-line subtle"><span id="bob-signal-status">reveal: no · abort: no</span></p>
            </article>
          </div>
          <section id="public-keys-card" class="card public-keys-card hidden">
            <div class="section-head">
              <div>
                <div class="eyebrow">Committed public keys</div>
                <h2>pk_X and pk_Y</h2>
              </div>
              <span class="pill">A · B</span>
            </div>
            <p class="hint">Computed from both parties' on-chain commitments.</p>
            <dl class="result-grid key-grid">
              <div>
                <dt>pk_X = A_X · B_X</dt>
                <dd id="pk-x"></dd>
              </div>
              <div>
                <dt>pk_Y = A_Y · B_Y</dt>
                <dd id="pk-y"></dd>
              </div>
            </dl>
          </section>
        </section>

        <section id="action-panel" class="card hidden">
          <div class="section-head">
            <div>
              <div class="eyebrow">Your turn</div>
              <h2>Protocol actions</h2>
            </div>
            <button id="refresh-btn" class="ghost">Refresh</button>
          </div>
          <p id="turn-hint" class="turn-hint"></p>
          <div class="action-row">
            <button id="prepare-btn" class="primary">Prepare &amp; commit</button>
            <button id="reveal-btn" class="secondary">Signal reveal</button>
            <button id="abort-btn" class="danger">Signal abort</button>
          </div>
          <p id="action-status" class="status"></p>
        </section>

        <section id="result-card" class="card result-card hidden">
          <div class="section-head">
            <div>
              <div class="eyebrow">Branch result</div>
              <h2 id="result-title">Result</h2>
            </div>
            <span id="result-branch" class="pill"></span>
          </div>
          <dl class="result-grid">
            <div><dt>Recovered counterparty share</dt><dd id="result-share"></dd></div>
            <div><dt>Derived private scalar</dt><dd id="result-secret"></dd></div>
            <div><dt>Public key g<sup>sk</sup></dt><dd id="result-public"></dd></div>
            <div><dt>Commitment check</dt><dd id="result-verified"></dd></div>
          </dl>
        </section>

        <section class="card">
          <div class="section-head">
            <div>
              <div class="eyebrow">Timeline</div>
              <h2>Protocol log</h2>
            </div>
          </div>
          <ul id="log" class="log-list"></ul>
        </section>
      </div>
    </div>
  `;

  $("login-btn").addEventListener("click", () => void login());
  $("logout-btn").addEventListener("click", () => void logout());
  $("create-btn").addEventListener("click", () => void createSession());
  $("load-btn").addEventListener("click", () => void loadSession($("session-id").value));
  $("prepare-btn").addEventListener("click", () => void prepareAndCommit());
  $("reveal-btn").addEventListener("click", () => void sendSignal(Signal.reveal));
  $("abort-btn").addEventListener("click", () => void sendSignal(Signal.abort));
  $("refresh-btn").addEventListener("click", () => void refreshSession());
}

setupDom();
renderLog();

if (import.meta.env.DEV) {
  // AuthClient filters ICRC-29 messages internally. This log is only here to
  // make transport problems visible in the browser console during development.
  window.addEventListener("message", (event) => {
    if (!/id\.ai|ic0\.app|localhost/.test(event.origin)) return;
    const kind =
      event.data && typeof event.data === "object"
        ? event.data.method ?? event.data.jsonrpc ?? Object.keys(event.data).join(",")
        : typeof event.data;
    console.debug("[auth message]", event.origin, kind);
  });
}

void initAuth();
