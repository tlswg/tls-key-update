# Spec - Model Mapping

This note maps the PROMELA models in `model/` to the normative text in
`draft-ietf-tls-extended-key-update`, focusing on the EKU message/state
machine text, DTLS Section 6, Section 11 authentication interactions, and
Appendix B.

The mapping is intentionally operational: it points to which model transitions
represent which spec steps/state-machine edges, and what is abstracted or out of
scope.

## Property Overview (What We Verify)

The current SPIN models focus on three core properties:

- `no_unexpected`: no run should set the abstract error flag `unexpected`
  (used to represent protocol-level `"unexpected_message"` handling).
- `no_illegal_parameter`: no benign run should set the abstract error flag
  `illegal_parameter` (used for wrong negotiated KeyShareEntry group).
- `epoch_consistency`: if a run finishes without `unexpected`, both peers end in
  synchronized directional epoch state (`I/A.tx == R/B.rx` and
  `I/A.rx == R/B.tx`).
- `no_deadlock`: liveness/progress property (model-specific terminal condition).

## Synchronized Generation/Epoch Assumption

All three models assume that, outside an EKU exchange, both traffic directions
use the same numeric generation or epoch identifier:

- TLS: `A.send = B.receive = E` and `B.send = A.receive = E`.
- Single-initiator DTLS:
  `I.tx = R.rx = E` and `R.tx = I.rx = E`.
- Crossed-requests DTLS:
  `A.tx = B.rx = E` and `B.tx = A.rx = E`.

This is an assumption about numeric generation/epoch identifiers, not about
cryptographic key equality. Send and receive traffic keys remain
direction-specific and cryptographically distinct.

The assumption follows the draft's EKU-only state machine:

- once EKU has been negotiated, the classic TLS/DTLS `KeyUpdate` mechanism
  **MUST NOT** be used;
- receiving a classic `KeyUpdate` is modeled as an
  `"unexpected_message"` error;
- classic `KeyUpdate` is the mechanism that would otherwise permit one traffic
  direction to advance independently;
- an EKU exchange advances both directions, although temporary `tx`/`rx`
  mismatches are expected while the exchange is in progress;
- after successful completion, the state machines return to a synchronized
  generation/epoch boundary.

The DTLS models expose four separate initialization parameters so that roles
and directions remain explicit:

- `extended_key_update.pml`:
  `INIT_RX_I`, `INIT_TX_I`, `INIT_RX_R`, `INIT_TX_R`;
- `extended_key_update_crossed.pml`:
  `INIT_RX_A`, `INIT_TX_A`, `INIT_RX_B`, `INIT_TX_B`.

These parameters are **not independent configuration knobs**. If overridden,
all four parameters for the selected model MUST be set to the same value. For
example:

```sh
spin -DINIT_RX_I=3 -DINIT_TX_I=3 \
     -DINIT_RX_R=3 -DINIT_TX_R=3 ...
```

and:

```sh
spin -DINIT_RX_A=3 -DINIT_TX_A=3 \
     -DINIT_RX_B=3 -DINIT_TX_B=3 ...
```

Using directionally matching but numerically different initial values, such as
`INIT_TX_I=INIT_RX_R=0` and `INIT_TX_R=INIT_RX_I=3`, is outside the supported
model assumptions. Local completion assertions and `epoch_consistency`
intentionally reject such a configuration.

## PHA/EA Modeling Assumptions

The models include an abstract representation of post-handshake authentication
mechanisms to check EKU sequencing/progress constraints without modeling crypto
internals.

- **PHA abstraction (RFC 8446 §4.6.2-inspired):**
  - represented as `PHAReq -> PHAFin`.
  - message-level certificate chain and `CertificateVerify` details are not modeled.
- **EA abstraction (RFC 9261-inspired):**
  - request/response path represented as `EAReq -> EAFin`.
  - spontaneous server authentication is represented as one-way `EAFin` from server.
  - in DTLS models, spontaneous `EAFin` is acknowledged with `ACK`.
- **PHA/EKU sequencing rule in all models:**
  - EKU progress is blocked only while PHA is pending.
  - EKU requests observed during pending PHA are deferred and resumed afterwards.
  - PHA is not initiated while EKU is locally in progress.
- **EA/EKU sequencing rule in all models:**
  - EA does not block EKU progress and is not blocked by EKU progress.
  - This matches the current draft text that makes the EA interface epoch-aware
    and imposes no serialization requirement between EKU and EA.
- **Out-of-scope for PHA/EA in all models:**
  - certificate object/content validation,
  - Finished MAC/transcript cryptography,
  - exporter-secret/key schedule internals and API behavior.

## Negative/Error-Path Modeling

All three models include abstract message types for current normative error
paths:

- `KeyUpdate`: classic TLS/DTLS KeyUpdate after EKU negotiation; receiving it
  sets `unexpected`.
- `UnknownEKU`: ExtendedKeyUpdate with an unknown/unexpected subtype; receiving
  it sets `unexpected`.
- `EarlyEKU`: ExtendedKeyUpdate received before the sender has sent Finished;
  receiving it sets `unexpected`.
- `BadGroupReq` / `BadGroupResp`: EKU request/response carrying a KeyShareEntry
  for a group other than the negotiated group; receiving either sets
  `illegal_parameter`.

These negative inputs are disabled by default via `INJECT_ERRORS=0` so the normal
`no_unexpected` / `no_illegal_parameter` checks describe benign protocol runs.
Set `-DINJECT_ERRORS=1` to exercise the abstract error transitions; in that
configuration the corresponding safety claims are expected to fail.

Model-to-property coverage:

- `model/tls13_extended_key_update.pml`:
  - `no_unexpected`
  - `no_illegal_parameter`
  - `key_sync` (TLS analogue of end-state consistency)
- `model/extended_key_update.pml`:
  - `no_unexpected`
  - `no_illegal_parameter`
  - `epoch_consistency`
- `model/extended_key_update_crossed.pml`:
  - `no_unexpected`
  - `no_illegal_parameter`
  - `epoch_consistency`
  - `no_deadlock`

## `model/tls13_extended_key_update.pml`

**Short model profile**
- Purpose: minimal TLS 1.3 EKU state-machine model (no DTLS ACK/retention mechanics).
- Use this model when you want to validate TLS EKU sequencing and crossed-request
  key-share tie-break behavior at low state-space cost.
- Primary checks: `no_unexpected`, `no_illegal_parameter`, `key_sync`.

**Spec anchors**
- Appendix B.1.1 (TLS 1.3 Initiator State Machine)
- Appendix B.1.2 (TLS 1.3 Responder State Machine)
- Figure 3 / Section 5.1 (key update ordering overview)

**Configuration**
- You can override `E`, `INITIATE_A`, `INITIATE_B`, `KX_A`, `KX_B`, `APP_QUOTA`,
  `ENABLE_PHA`, `PHA_TRIGGER_B`, `ENABLE_EA`, `EA_TRIGGER_A`, `EA_TRIGGER_B`,
  `EA_SPONT_TRIGGER_B`, `INJECT_ERRORS` via `spin -D...`.

**Model entities**
- Peers: `PeerA`, `PeerB` (either can initiate)
- Messages: `Req`, `Resp`, `Fin` (and optional `APP`, `PHAReq`, `PHAFin`,
  `EAReq`, `EAFin`, plus negative-path `KeyUpdate`, `UnknownEKU`,
  `EarlyEKU`, `BadGroupReq`, `BadGroupResp`)
- Abstracted `KeyShareEntry.key_exchange`: `KX_A`, `KX_B` carried in `Req`
- Key state (per peer): `send_key`, `receive_key` (counters representing “current/new”)
- Abort flags: `unexpected` (represents `"unexpected_message"`),
  `illegal_parameter` (represents `"illegal_parameter"`)

**State/step mapping**
- **B.1.1 START → WAIT_RESP**: initiation is `a2b ! Req, send_key, KX_A` / `b2a ! Req, send_key, KX_B`
- **B.1.1 WAIT_RESP (crossed requests)**:
  - receive `Req` while `updating` and `initiated`:
    - `peer_kx < local_kx` ⇒ ignore (`skip`)
    - `peer_kx == local_kx` ⇒ `unexpected=true`
    - `peer_kx > local_kx` ⇒ “abandon local update; act as responder”:
      send `Resp` + advance responder `send_key`
- **B.1.2 Responder START/RESPOND**: on receiving `Req` while not updating:
  send `Resp` and advance responder `send_key` (matches “derive new secrets; update SEND keys”)
- **B.1.1 Initiator receives Resp**: `receive_key++`, send `Fin` (still under old keys), then `send_key++`
- **B.1.2 Responder receives Fin**: `receive_key++` and finish
- **RFC 8446 §4.6.2 abstraction (optional)**:
  - `PHAReq` models a post-handshake `CertificateRequest`-like trigger
  - `PHAFin` models a post-handshake Finished-like response
  - guards/deferral enforce:
    - no `PHAReq` while EKU is locally in progress,
    - no EKU progress while PHA is pending,
    - EKU `Req` observed during outstanding PHA is deferred and resumed afterward.
- **RFC 9261 abstraction (optional)**:
  - request/response EA: `EAReq` -> `EAFin` (app-triggered, both directions),
  - spontaneous server EA: server sends `EAFin` without prior `EAReq`,
  - EA is not serialized with EKU.
- **Error paths**:
  - `KeyUpdate`, `UnknownEKU`, and `EarlyEKU` drive `unexpected=true`.
  - `BadGroupReq` and `BadGroupResp` drive `illegal_parameter=true`.

**Important abstraction choices**
- All four TLS directional generation counters start at the same numeric value
  `E`: `A.send = B.receive = E` and `B.send = A.receive = E`. This is a
  generation-number abstraction and does not mean that both TLS directions use
  the same traffic key.
- `key_sync` compares matching communication directions:
  `A.send == B.receive` and `A.receive == B.send`.
- The TLS wire detail “Fin encrypted under old keys” is represented only by the
  ordering of increments (no crypto).
- Classic `KeyUpdate`, unexpected EKU subtype, EKU-before-Finished, and
  wrong-group KeyShareEntry handling are represented as abstract negative-path
  messages. They do not model full handshake framing or concrete group encodings.
- PHA is modeled as an abstract two-message control flow (`PHAReq`/`PHAFin`);
  certificate chains, transcript/MAC key derivation, and authenticator APIs are
  not modeled.
- EA is modeled as an abstract two-message control flow (`EAReq`/`EAFin`) plus
  optional spontaneous server `EAFin`; it is deliberately independent of EKU
  serialization. Full RFC 9261 message structures, epoch-aware API behavior, and
  crypto transcript binding are out of scope.

## `model/extended_key_update.pml`

**Short model profile**
- Purpose: DTLS EKU model for one initiator and one responder (no crossed requests).
- Use this model when you want to validate DTLS retransmission/ACK flow and
  epoch-retention handling without crossed-requests complexity.
- Primary checks: `no_unexpected`, `no_illegal_parameter`, `epoch_consistency`.

**Spec anchors**
- Section 6 (DTLS 1.3 Considerations), steps 1–7
- Appendix B.2.2 (DTLS initiator state machine)
- Appendix B.2.3 (DTLS responder state machine)
- Appendix B.2.1 (APP acceptance/retention rule)

**Configuration**
- You can override `INIT_RX_I`, `INIT_TX_I`, `INIT_RX_R`, `INIT_TX_R`, `DROPS`, `REQ_RETRIES`, `FIN_RETRIES`, `RESP_RETRIES`, `DEFER_RESP`, `APP_QUOTA_I`, `APP_QUOTA_R`, `INJECT_ERRORS` via `spin -D...`.
- The four `INIT_RX_*`/`INIT_TX_*` values are role-explicit aliases for one
  common initial epoch and MUST be overridden together with the same value.
- Additional auth-related knobs: `ENABLE_PHA`, `PHA_TRIGGER_R`, `ENABLE_EA`,
  `EA_TRIGGER_I`, `EA_TRIGGER_R`, `EA_SPONT_TRIGGER_R`.

**Model entities**
- Processes: `Initiator`, `Responder`, `Network`
- Messages: `Req`, `Resp`, `Fin`, `ACK`, `APP`
- Optional auth messages: `PHAReq`, `PHAFin`, `EAReq`, `EAFin`
- Negative-path messages: `KeyUpdate`, `UnknownEKU`, `EarlyEKU`,
  `BadGroupReq`, `BadGroupResp`
- Epoch state:
  - initiator: `rx_epoch_i`, `tx_epoch_i`, `old_rx_i`, `retain_old_i`
  - responder: `rx_epoch_r`, `tx_epoch_r`, `old_rx_r`, `retain_old_r`
- Loss/reordering: `Network` with `drops_left` and two paths each direction

**State/step mapping**
- **§6 step 1 (Req + retransmit)**:
  - `Initiator` sends `Req` tagged with `tx_epoch_i`
  - retransmits controlled by `req_retries`
- **§6 step 2 (Resp, optional duplicates, optional defer)**:
  - `Responder` on `Req` either sends `Resp` tagged with `tx_epoch_r` or,
    when `DEFER_RESP=1`, may ACK the `Req` first and later send/retransmit
    `Resp` up to `RESP_RETRIES`.
  - Initiator treats that ACK as delivery confirmation for `Req` and stops
    retransmitting `Req` while continuing to wait for `Resp`.
  - A late old-epoch ACK after `Resp` is ignored in `WAIT_ACK`.
- **§6 step 3 (Resp is implicit ACK of Req; initiator updates RECEIVE/epoch)**:
  - on `Resp` with `e == rx_epoch_i`: initiator activates retention (`old_rx_i=rx_epoch_i; retain_old_i=1`), bumps `rx_epoch_i`, then sends `Fin`
- **§6 step 4 (Fin + retransmit)**:
  - initiator sends `Fin` tagged with the old `tx_epoch_i` (`old_tx_i`)
  - retransmits controlled by `fin_retries`
- **§6 step 5 (responder ACK)**:
  - responder sends `ACK` tagged with its (new) `tx_epoch_r` after processing `Fin`
- **§6 step 6 (responder updates send key/epoch and receive keys)**:
  - modeled as `rx_epoch_r++` and `tx_epoch_r++` after accepting `Fin`
- **§6 step 7 (initiator updates send key/epoch on ACK)**:
  - initiator sets `tx_epoch_i = rx_epoch_i` upon receiving `ACK`
- **Appendix B.2.1 APP acceptance rule**:
  - Receive-side checks are implemented as “accept-or-discard”:
    accept if `e==rx` or (`retain_old && e==old_rx`); otherwise discard.

**Important abstraction choices**
- This file models a single EKU exchange between a fixed Initiator/Responder.
  Crossed-requests (both sides initiate) are modeled separately in
  `model/extended_key_update_crossed.pml`.
- “Initiator MUST NOT defer derivation of the secrets” is represented by treating
  the `Resp` handling as atomic: on `Resp`, the initiator immediately activates
  retention, bumps `rx`, and sends `Fin` (no intermediate states).
- Retention end follows Appendix B.2:
  - initiator clears retention on `ACK` (step 7 / Appendix B.2.2)
  - responder clears retention on first `APP` received at the new `rx` (Appendix B.2.3)
  The model does not attempt to model DTLS record-layer replay windows.
- PHA/EA are abstract control flows:
  - PHA: `PHAReq`/`PHAFin`
  - EA request/response: `EAReq`/`EAFin`
  - spontaneous server EA: responder sends `EAFin` without prior `EAReq`, and
    initiator acknowledges with `ACK`.
- EKU vs PHA sequencing is encoded via `PHA_PENDING`; EKU transitions are
  blocked while PHA is outstanding and deferred requests are resumed after PHA
  completion.
- EA intentionally does not participate in that guard.
- Classic `KeyUpdate`, unexpected EKU subtype, EKU-before-Finished, and
  wrong-group KeyShareEntry handling are represented as abstract negative-path
  messages.

## `model/extended_key_update_crossed.pml`

**Short model profile**
- Purpose: DTLS EKU model with simultaneous initiation and crossed-request resolution.
- Use this model when you want to stress crossed requests, loss/reordering, retry
  bounds, and progress/liveness edge cases.
- Primary checks: `no_unexpected`, `no_illegal_parameter`, `epoch_consistency`,
  `no_deadlock`.

**Spec anchors**
- Appendix B.2.1 (Crossed requests rule)
- Appendix B.2.2 / B.2.3 (DTLS state machines)
- Section 6 steps 1–7 (message-level semantics)

**Configuration**
- You can override `INIT_RX_A`, `INIT_TX_A`, `INIT_RX_B`, `INIT_TX_B`,
  `DROPS`, `REQ_RETRIES`, `FIN_RETRIES`, `RESP_RETRIES`, `DEFER_RESP`,
  `APP_QUOTA`, `KX_A`, `KX_B`, `INJECT_ERRORS` via `spin -D...`.
- The four `INIT_RX_*`/`INIT_TX_*` values are role-explicit aliases for one
  common initial epoch and MUST be overridden together with the same value.
- Additional auth-related knobs: `ENABLE_PHA`, `PHA_TRIGGER_B`, `ENABLE_EA`,
  `EA_TRIGGER_A`, `EA_TRIGGER_B`, `EA_SPONT_TRIGGER_B`.

**Model entities**
- Peers: `PeerA`, `PeerB` (either can initiate; both enabled by default)
- Messages: `Req`, `Resp`, `Fin`, `ACK`, `APP`
- Optional auth messages: `PHAReq`, `PHAFin`, `EAReq`, `EAFin`
- Negative-path messages: `KeyUpdate`, `UnknownEKU`, `EarlyEKU`,
  `BadGroupReq`, `BadGroupResp`
- Abstracted `KeyShareEntry.key_exchange`: `KX_A`, `KX_B` carried in `Req`
- Epoch state per peer: `rx`, `tx`, `old_rx`, `retain_old`
- Abort flags: `unexpected` (represents `"unexpected_message"`),
  `illegal_parameter` (represents `"illegal_parameter"`)

**Crossed-requests mapping (Appendix B.2.1)**
- When a peer is in the “initiated and waiting for Resp” mode and receives a
  `Req` from the other peer:
  - `peer_kx < local_kx` ⇒ ignore (no response)
  - `peer_kx == local_kx` ⇒ `unexpected=true`
  - `peer_kx > local_kx` ⇒ abandon local update and act as responder (send `Resp`)
- Retransmitted `Req` from the peer during an ongoing update is treated as a
  duplicate only if it carries the same `peer_kx_active`; then the model
  retransmits `Resp` or, if a deferred response has not yet been sent, ACKs the
  `Req` again.

**DTLS epoch/ACK mapping (Section 6 + Appendix B.2)**
- Initiator-side:
  - `Req` tagged with `tx`
  - on `Resp [e==rx]`: secrets are derived immediately (no “defer derivation” states)
  - on `Resp [e==rx]`: retention `old_rx=rx; retain_old=1; rx++`
  - send `Fin [tag=old tx]`
  - on `ACK [e==rx]`: `tx=rx`, clear retention, and finish
- Responder-side:
  - on `Req`: send `Resp [tag=tx]`, or when `DEFER_RESP=1`, ACK `Req` first
    and later send/retransmit `Resp`.
  - on `Fin [e==rx]`: `old_rx=rx; retain_old=1; rx++; tx++;` then send `ACK [tag=tx]`
  - on duplicate `Fin` from the old epoch during retention: retransmit `ACK`

**Configuration knobs (trade off realism vs state space)**
- `DROPS`: total number of drops in the network (loss model)
- `REQ_RETRIES`, `FIN_RETRIES`: bounded retransmissions for handshake messages
- `RESP_RETRIES`: bounded retransmissions for a deferred response
- `DEFER_RESP`: enables the optional DTLS ACK-then-Resp path
- `APP_QUOTA`: extra APP sends to exercise retention under reordering

**Known limitations / out-of-scope**
- PHA and EA are intentionally abstracted; certificate objects, Finished MAC
  derivation, exporter transcript binding, and authenticator payload validation
  are not modeled.
- Classic `KeyUpdate`, unexpected EKU subtype, EKU-before-Finished, and
  wrong-group KeyShareEntry handling are represented only as abstract negative
  messages.

## Transcript Hash Updates

This section maps the changes from PR #95 to the current
SPIN models.

**What PR #95 changes in the spec**
- Introduces per-generation transcript binding:
  `transcript_hash_N+1 = Transcript-Hash(transcript_hash_N || Req || Resp)`.
- Updates key schedule inputs to use `transcript_hash_N+1`.
- Clarifies post-handshake client auth / exported authenticators behavior after EKU.
- Adds sequencing constraints between EKU and post-handshake certificate request flow.

**Current model coverage (what remains valid)**
- State-machine ordering for EKU (`Req -> Resp -> Fin -> ACK` in DTLS; TLS flow).
- Crossed-requests tie-break behavior (`key_exchange` comparison).
- DTLS deferred response path (`ACK` for `Req`, later `Resp` retransmission).
- PHA/EKU serialization and EA/EKU non-serialization.
- Abstract negative-message handling for classic KeyUpdate, unexpected EKU
  subtype, EKU-before-Finished, and wrong KeyShareEntry group.
- Epoch/key-state synchronization checks (`no_unexpected`, `epoch_consistency`, etc.).

**Out-of-scope in current models**
- Cryptographic key schedule details:
  - no HKDF inputs, no transcript hash state, no `transcript_hash_N` evolution.
- PHA / Exported Authenticator concrete protocol content:
  - no certificate objects, no Finished MAC-key derivation, no exporter-secret API.
- Message-level sequencing constraints around EKU vs PHA are abstractly modeled
  in all three models via `PHA_PENDING` guards and deferred EKU request
  handling; cryptographic transcript linkage remains out of scope.
- EA/EKU concurrency is represented structurally, but the epoch-aware EA API and
  exporter-secret selection are not modeled.

**When model updates become necessary**
- If verification goals include transcript-binding correctness, add an abstract
  `transcript_gen` (or equivalent) and enforce monotonic update on each successful
  EKU exchange (`Req+Resp` pair).
- If verification goals include concrete PHA/EA cryptographic checks, add
  symbolic transcript/exporter epochs and explicit authenticator validation.

## Appendix C (Security Goals) vs. Models

Appendix C provides an *informal* description of EKU security goals. The PROMELA
models in `model/` primarily check **protocol ordering**, **epoch/key-state
synchronization**, and **crossed-requests corner cases** under loss/reordering.
They do **not** attempt to model cryptography, an active attacker, or
application-layer authentication.

**Threat model in the SPIN models:** benign peers and a lossy/reordering network
only. There is no MitM, no message forgery/modification, and no key compromise
adversary.

### C.1 Post-Compromise Security (PCS)

**Spec goal:** after a transient compromise of current traffic keys, EKU yields
fresh keys (from fresh ephemeral KX) so the attacker cannot derive the new
keying material (assuming no active MitM during the EKU run).

**Model coverage:** out of scope.
- The models do not represent an attacker with key material, compromise windows,
  or MitM substitution of EKU messages.
- Cryptographic derivation is abstracted away (counters/epochs only), so “cannot
  derive new keys from old keys” is not expressible in the model.

**SPIN-checkable proxy (sanity only):**
- The protocol completes and both sides synchronize on a new epoch/generation
  (`key_sync` / `epoch_consistency`), i.e., the update is *well-formed* at the
  state-machine level. This is necessary for PCS, but not sufficient.

### C.2 Key Freshness and Cryptographic Independence

**Spec goal:** each EKU uses fresh ephemeral KX material and produces traffic
keys independent of previous ones (no forward/backward derivability across
epochs).

**Model coverage:** only structural/protocol-level aspects.
- The models can only capture **protocol-level progression** (epochs/key
  generations advance monotonically and end synchronized).
- They do not and cannot prove “fresh ephemeral KX” or cryptographic
  independence (no secrets, no HKDF/KDF, no compromise queries).

**SPIN-checkable proxies (protocol-level invariants):**
- **Monotonicity/progress:** epochs/generations never decrease.
- **No double-advance on crossed requests:** the tie-break rule prevents both
  sides from advancing twice due to simultaneous initiation.
- **End-state consistency:** after completion, both sides agree on the active
  epoch/generation (`key_sync` / `epoch_consistency`).

### C.3 Elimination of Standard KeyUpdate

**Spec goal:** once EKU is negotiated, classic TLS 1.3 `KeyUpdate` must not be
used; receiving a classic `KeyUpdate` then is an `"unexpected_message"`.

**Model coverage:** abstract negative-path coverage.
- The models include a `KeyUpdate` message type that represents receiving the
  classic TLS/DTLS KeyUpdate after EKU negotiation.
- Receiving `KeyUpdate` sets `unexpected=true`; with `-DINJECT_ERRORS=1`, the
  `no_unexpected` claim is expected to fail on that injected bad input.

### C.4 Detecting Divergent Key State

**Spec goal:** post-handshake authentication and exported authenticators (Section
11) can detect if peers derived different updated keys (e.g., due to active
interference).

**Model coverage:** only “no divergence in benign runs”.
- The models check **consistency of key state after completion** (e.g.,
  `key_sync` / `epoch_consistency`) assuming no malicious modification of the
  handshake messages.
- They do not model Finished computations, authenticators, exporter secrets, or
  an attacker that causes divergence and is then detected.

**SPIN-checkable proxies (consistency, not detection):**
- If the run completes without `unexpected`, both sides converge to the same
  epoch/generation (`key_sync` / `epoch_consistency`).
- Modeling “detection” would require an additional abstraction layer (e.g., a
  symbolic `secret_id` plus an explicit “authenticator check” step that fails on
  mismatch), which is not present.
