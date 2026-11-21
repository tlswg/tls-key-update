# Specification–model mapping

The entry points model the EKU exchange and the post-handshake interactions in
`draft-ietf-tls-extended-key-update.md`. They include a shared operational model,
`eku_protocol.pml`, so that ACK handling and authentication rules do not diverge
between the single-initiator, crossed-request, and TLS variants.

The DTLS entry points follow Step 7 of the DTLS procedure: any record that the
initiator deprotects under its new receive epoch completes the exchange. Earlier
model versions waited for the explicit ACK of the finish message and buffered
new-epoch handshake messages until then; their results and state counts cannot
be compared with this model.

## Entry points and roles

| Entry point | Transport | Default initiation |
| --- | --- | --- |
| `extended_key_update.pml` | DTLS, loss/reordering | A initiates, B responds |
| `extended_key_update_crossed.pml` | DTLS, loss/reordering | Both initiate; greater key share wins |
| `tls13_extended_key_update.pml` | Ordered reliable TLS | Both may initiate |

A is the TLS client and B the TLS server, independently of their EKU roles.
Each endpoint executes the same `Peer` process. After local EKU completion it
continues receiving messages and servicing authentication; completion does not
make post-EKU PHA unreachable.

Directional traffic epochs start at a common numeric value. DTLS entry points
preserve the `INIT_RX_I`/`INIT_TX_I`/`INIT_RX_R`/`INIT_TX_R` and
`INIT_RX_A`/`INIT_TX_A`/`INIT_RX_B`/`INIT_TX_B` parameters and reject unequal
initial values. TLS uses `E`. Equal numeric epochs do not mean equal directional
keys. The authentication/exporter generation starts at zero regardless of the
initial traffic epoch; the epoch-three regression checks this separation.

## Local state and abstraction boundary

`peer[id]` stores the endpoint's own phase, TX/RX epochs, old receive-key
retention, outgoing handshake transmissions, reassembly, pending ACKs, PHA state,
EA contexts, and CID selection. Protocol actions do not consult the other
endpoint's PHA or EA state. Cross-peer reads are used by the transport model,
termination/properties, and the deliberately faulty `FAULT_GLOBAL_PHA` mutation.

The model covers one successful EKU generation, at most one PHA exchange, one
requested EA in each direction, one unsolicited server EA, and one server CID
advertisement. It does not model real signatures, MACs, KDFs, certificate parsing,
multiple connections, or active attackers that forge authenticated records.
Generation labels express the required association; they are not a cryptographic
security proof.

## EKU and transmission ordering

| Specification action | Model action |
| --- | --- |
| Wait for earlier independent transmissions | `OtherHS`, CID requests/advertisements, PHA response transmissions and an abandoned crossed Req must be acknowledged before the relevant Req/Resp/Fin action |
| Initiator receives response | Implicitly acknowledge Req, derive immediately, advance RX, enter `NEED_FINISH` |
| DTLS initiator sends finish | Keep old TX; enter `WAIT_ACK` |
| DTLS responder receives finish | Implicitly acknowledge Resp, advance both epochs, send a record-specific ACK |
| DTLS initiator deprotects any record under the new receive epoch (Step 7) | Treat Fin as acknowledged, advance TX and complete locally, then process the record |
| TLS responder sends response | Advance TX after sending under the old keys |
| TLS initiator sends finish | Advance TX immediately after sending under the old keys |
| TLS responder receives finish | Advance RX and complete locally |

Independent handshake creation is restricted to before the exchange or after
local completion. PHA crossing an EKU request uses the explicit exception and
completes under the older context before the exchange advances. `OtherHS` is an
abstract independent handshake transmission, not a new TLS message definition.

Handshake sequence numbers increase on new messages and do not reset at EKU.
Messages ahead of the next expected sequence are discarded without ACK; their
senders retain responsibility for retransmission. Earlier messages are treated
as duplicates and re-ACKed if still decryptable. Fin establishes that the peer
received the preceding response.

## Crossed requests

Requests cross when both endpoints send Req before receiving the peer's Req.
Two independent decisions apply to the Req that an endpoint then receives in
`WAIT_RESPONSE`. The DTLS handshake layer checks the handshake sequence number
and advances `next_receive_seq`. Only afterwards does the EKU tie-break compare
the key shares. The tie-break decides what happens to the EKU operation. It
does not change how the message is delivered or acknowledged.

| Specification rule | Model action |
| --- | --- |
| The request with the lower `key_exchange` value is ignored | A Req whose share is lower than the local share changes no EKU state |
| Equal values are a protocol violation | `unexpected` is raised |
| The sender of the ignored request abandons its exchange and acts as the responder | `initiated` is cleared and the endpoint enters `NEED_RESPONSE` |
| DTLS: the ignored request is sequenced and acknowledged, including its retransmissions | The sequence number is consumed before the tie-break; the winner calls `acknowledge_incoming`; duplicates are re-ACKed |
| DTLS: the abandoned request is retransmitted until it is acknowledged | `outstanding[Req]` stays set at the endpoint that lost the tie-break |
| DTLS: the response is not sent before the abandoned request is acknowledged | The `NEED_RESPONSE` action requires `!outstanding[Req]` |
| DTLS: the peer's request is acknowledged while the response is held back | The losing endpoint ACKs the winning Req when it processes it with its own Req still outstanding |

The abandoned request is therefore treated like any other earlier handshake
transmission, as specified in "Handshake Ordering Across an EKU". An assertion
at the receipt of Fin checks the consequence: no abandoned request is still
outstanding when the responder completes. In TLS there are no outstanding
transmissions, so the last four rows have no effect and the losing endpoint
responds immediately.

Model versions up to 18 November 2026 used a weaker rule. The losing endpoint
could send Resp while its abandoned Req was unacknowledged, and Fin was taken
as an implicit acknowledgment of that Req. That variant also passed the
crossed-request profiles. The draft now specifies the stricter rule, and the
model follows it. State counts of the crossed profiles are not comparable
between the two variants.

Abandoning the exchange must not end retransmission of the abandoned request.
If the request is lost and not retransmitted, the peer never receives its
handshake sequence number and cannot process the Resp that follows it.

Key shares are a single constant byte per endpoint, used for the request and
for the response. The model therefore does not represent the bytewise unsigned
comparison of real `key_exchange` values, nor the requirement to discard the
key share of the abandoned request and generate a fresh one for the response.

## Record-specific acknowledgments and retention

Each emitted record receives a fresh opaque handle. The handle names a distinct
`(epoch, record sequence number)` pair in that direction. Its epoch and message
kind are recorded at the sender. An ACK identifies one such record and its epoch;
its payload's observer label is not used to decide what it acknowledges.
Retransmission uses a new record handle with the original handshake sequence,
epoch, and payload. An ACK still acknowledges only the record it names.

Completion at the initiator does not depend on which record an ACK names. Under
Step 7 the epoch of the received record decides, because the responder sends
under the new epoch only after it has processed Fin. The ACK of Fin is the usual
completing record. A late ACK for Req under the new epoch, a handshake message,
or application data completes the exchange in the same way. A record under the
pre-update epoch never does.

This is a bounded abstraction of record-number equality, not a wire-format model.
ACK lists contain one record in this model; arbitrary list packing and concrete
48-bit record sequence numbers are not modeled. There are 32 record handles per
endpoint. Bounds are asserted, never silently wrapped or reused.

An ACK referring to a higher epoch than its own record raises
`illegal_parameter`. Step 7 activates the new sending epoch before a new-epoch
record is processed, so no ACK is deferred; `acknowledge_incoming` asserts that
the acknowledged record's epoch does not exceed the sending epoch. The initiator
retransmits Fin under the old epoch until Step 7 completes and not afterwards.
Old receive keys remain available until a successfully processed
record in the new RX epoch permits retirement. Invalid old-epoch DTLS records
are discarded; TLS delivery is ordered and must match the current receive keys.

## PHA, fragments, and context association

Only B generates PHA requests. Its `pha_waiting` state has no immediate effect
on A. A learns about PHA only through received messages. A new-epoch request
received in `WAIT_ACK` first completes the exchange at A (Step 7). A then
processes it using the new context and responds under the new epoch. Nothing is
buffered, and Fin is not retransmitted afterwards. B still re-ACKs Fin
retransmissions that A sent earlier.

The ordering rules for PHA and EKU are guards on the model actions. B creates a
request only in `IDLE` or after local completion. Neither endpoint initiates EKU
while a PHA exchange is outstanding locally. For a request that crosses an EKU
request, B withholds Resp while its request is outstanding, and A withholds Fin
until its response has been sent and acknowledged. Two assertions check the
result: B never processes Fin while its request is outstanding, and A's
generation matches the request when A responds. Profiles place the request
before EKU, crossing the EKU request, and after EKU, with either the client or
the server as EKU initiator.

PHA records carry separate MAC-generation and transcript-generation labels.
Creation checks the client's selected context; verification checks both labels
against the server's saved request context. These labels remain distinct from
the record epoch. A response is not considered successfully authenticated merely
because it arrived or because both traffic epochs eventually match.

`FRAGMENT_PHA=1` splits the CertificateRequest abstraction into two fragments.
Each fragment has a distinct record handle, the same handshake sequence and
unchanged context. Reassembly accepts either order and retransmitted fragments.
An explicit ACK for one fragment does not acknowledge the other fragment;
receipt of PHAFin implicitly acknowledges the complete request. A single
new-epoch fragment is a deprotected record and completes the exchange like any
other record. This covers a
bounded two-fragment abstraction, not arbitrary lengths, overlapping ranges,
PMTU changes, or the complete DTLS reassembly implementation.

## Exported Authenticators

EA requests and authenticators use separate `application` channels. They never
produce DTLS handshake ACKs. These channels represent a reliable authenticated
application transport, which is an explicit assumption rather than a property
of raw DTLS application data. Application-specific loss recovery and wire
encodings of generation identifiers are outside this model.

Requesters save their selected exporter generation. Responders capture a derived
context for that generation when receiving a request; delivery may wait until
EKU has completed. Requested responses have distinct operation identifiers;
unsolicited server authenticators use a different identifier. Verifiers use the
selected generation, not their current record epoch or current exporter.
A future generation can wait for local availability without blocking EKU.
`EXPIRE_OLD_EXPORTER=1` makes old verification contexts unavailable after local
completion; verification then fails explicitly as an application operation.
Already captured reply contexts remain available for the modeled operation.

## Connection IDs and ignored tickets

CID selection is separate from TX/RX epochs. B registers CID 1 before advertising
it; A uses it for subsequent records when `CID_IMMEDIATE=1`. `CID_TIMING=1` makes
B advertise the CID before it handles EKU. A's Fin and its retransmissions then
use the new CID under the old epoch and keys. With the default `CID_TIMING=2`
the advertisement is sent under the new epoch. If the Fin ACK was lost, it
completes the exchange at A and is acknowledged under the new sending epoch.
The model retains routing for CID 0 and the issued CID; it does not specify or
verify a CID-retirement protocol, address migration, or a pool of arbitrary CIDs.

`ENABLE_CID_REQUEST=1` makes A request a CID before initiating EKU. The request's
ACK permits EKU to proceed; actual CID delivery occurs after B's local EKU
completion. Request acknowledgment and request fulfillment are separate states.

`ENABLE_TICKET=1` deliberately represents an otherwise-valid ticket from a server
that violates the EKU sending prohibition. The client gives it no resumption
effect and still performs sequencing/ACK handling. This is a robustness profile,
not an example of an enabled post-handshake feature or a resumption model.

## Properties, witnesses, and timeout assumptions

- `protocol_safety`: no protocol error in benign runs, correct authentication
  contexts, no premature DTLS TX transition, and final directional epoch agreement.
- `new_epoch_confirms_finish`: a DTLS initiator completes only after the responder
  has processed Fin, and its TX remains unchanged while in `WAIT_ACK`.
- `authentication_context`: PHA transcript/MAC and EA exporter associations hold.
- `epoch_consistency`: matching directional epochs after both finish. This is
  also the key synchronization property. The former `key_sync` claim had the
  same formula and was removed.
- `no_deadlock`: eventual local EKU success **or bounded-retry abort**, not
  necessarily successful authentication or completion of every operation.
- `successful_completion`: both EKUs and all enabled operations complete, with
  all handshake transmissions resolved. Explicit EA context
  expiration counts as an operation failure handled by policy, not authentication
  success. Other profiles cannot use that exception unless expiration is enabled.

The `witness_*` claims intentionally assert that a target sequence never happens.
They must fail, and their replayed counterexamples establish that the target is
reachable **and subsequently completes**. They are not reported as safety bugs.
The `witness_*_completes_eku` claims show that, after loss of the Fin ACK, a
CertificateRequest, a NewConnectionId, application data, or an ACK naming
another record each complete the exchange at the initiator.

Mutations let a pre-update record complete the exchange, gate retransmissions on
the peer's PHA state, answer a new-epoch PHA request before completing the
exchange, select the wrong transcript or exporter, or retire old receive keys on
a CID change. These must fail their specified safety or completion claim for the
intended reason.

There are two timeout abstractions:

- Default: once record queues are empty, endpoint retransmission timers can fire
  independently. Finite retry exhaustion is possible, including under unfavorable
  scheduling. Safety is checked without assuming that every run succeeds.
- `ROUND_TIMEOUTS=1`: at global quiescence (`timeout`), due retries are scheduled
  for both endpoints. Each gets at most one retry opportunity in that round.
  Ordinary enabled message/operation processing runs before the next round.
  Strict completion claims use this idealized processing/time assumption and
  explicit drop/retry bounds; they do not prove progress under arbitrary CPU
  delays, arbitrary independent timer schedules, or unbounded packet loss.

All verification runs use exact storage and disable partial-order reduction by
default. Fairness is not silently enabled. Full-state search is exhaustive only
within the stated model and bounds. See `VERIFICATION.md` for commands and actual
results. The runner rejects resource/depth exhaustion and checks `errors:`;
SPIN's process exit status alone is not accepted as evidence of success.

## Running the models

```sh
bash scripts/spin-check.sh all
bash scripts/spin-check.sh regressions --output /tmp/eku-verification
bash scripts/spin-check.sh regressions --profile dtls-pha-loss
bash scripts/spin-check.sh dtls --define ENABLE_PHA=1 --define PHA_TIMING=2 \
  --define ROUND_TIMEOUTS=1 --claim successful_completion
```

The regression runner records exact flags, source SHA-256 values, logs and
self-contained source snapshots. Expected counterexamples are replayed against
those snapshots. `--bitstate` explicitly selects approximate exploration for
manual runs; it is forbidden for the regression suite. `--exhaustive` and
`--keep-tmp` remain compatibility options: searches are already exact by default,
and artifacts are retained. Former `RESP_WAIT_RETRIES` is no longer used; the
model tracks retransmittable flights instead of a separate responder polling
count. Existing single-initiator PHA/EA and APP parameter aliases are preserved.
