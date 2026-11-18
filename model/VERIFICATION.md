# SPIN verification of EKU post-handshake interactions

Verification date: 18 November 2026. Source checkout based on commit
`2206e44186edccc0f821f088b677cf2428d37800`. The model, runner, and draft changes are working-tree
changes; the hashes below identify the tested source independently of a future commit.

Tools: `Spin Version 6.5.2 -- 6 December 2019`; `gcc (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0`.

## Result

The regression suite completed **38 profiles and 78 claim checks**:
56 positive checks completed with zero errors; 22 checks produced their
expected counterexamples, which were replayed against self-contained source snapshots.
The latter are reachability witnesses, deliberately invalid input profiles, or
deliberately faulty model variants. They are not errors in the nominal model.

The standard CLI also passed 6 checks across TLS, DTLS, and crossed requests.
An additional DTLS/PHA run with two possible packet losses passed safety and
strict completion under the stated timeout assumption. A deliberately inadequate
depth limit was correctly rejected by the runner instead of being reported as a pass.

These results verify the bounded operational model, not the complete protocol or
its cryptographic security. See [SPEC-MAPPING.md](SPEC-MAPPING.md) for the mapping
and abstraction boundaries.

## What changed and what is demonstrated

This version replaces the results of 1 November 2026. That model completed the
DTLS exchange at the initiator only on the explicit ACK of Fin and buffered
new-epoch handshake messages until then. The model now follows Step 7 of the
DTLS procedure in the draft. State counts are not comparable between the two.

- The three entry points share `eku_protocol.pml`. PHA state is local to each
  endpoint; a server-side request cannot instantly change the client state.
- Any record that the DTLS initiator deprotects under its new receive epoch
  completes the exchange before the record is processed. Witnesses show this
  for a CertificateRequest, a single CertificateRequest fragment, a
  NewConnectionId, application data, and an ACK that names a record other than
  Fin, each after loss of the Fin ACK.
- No new-epoch record is buffered or left unacknowledged because of EKU. An
  assertion checks that an ACK never has to wait for the sending epoch.
- A record under the pre-update epoch never completes the exchange. The
  initiator completes only after the responder has processed Fin
  (`new_epoch_confirms_finish`, also part of `protocol_safety`).
- ACKs identify actual sent-record handles plus their epochs. Retransmissions
  have new record handles and the original handshake sequence, keys/epoch, and
  payload. Fin is retransmitted until Step 7 completes and not afterwards.
- PHA is checked with the request before EKU, crossing the EKU request, and
  after EKU, with the client or the server as EKU initiator, in TLS and DTLS.
- MAC and transcript generations are checked independently of record epochs.
  The epoch-three profile starts traffic epochs at 3 while authentication
  generation numbering starts at 0.
- EA objects use separate reliable authenticated application channels, retain
  the selected generation across EKU, and generate no DTLS handshake ACKs.
  Old verification contexts can expire with an explicit application failure.
- A CID advertised before EKU is used for Fin and its retransmissions under the
  old epoch and keys, without activating new send keys. CID request
  acknowledgment is distinct from delivery of the requested CIDs.
- The PHA request can be represented by two fragments, including reordering,
  retransmission, and partial explicit acknowledgment. A combined profile
  includes both fragment reassembly and a CID advertisement after EKU.
- Ignored-ticket handling is tested only as robustness against a peer that
  sends a ticket despite the negotiated prohibition. Resumption is not modeled.
- `epoch_consistency` is also the key synchronization property. The former
  `key_sync` claim had the same formula and was removed.

One important reliability detail is preserved for crossed requests: abandoning
the losing EKU operation does not abandon delivery of its handshake sequence
number. Otherwise a lost losing Req can leave a gap before that sender's Resp.
The model continues the appropriate delivery/retransmission until acknowledgment;
this should remain explicit when implementing the draft's collision rules.

The sequence represented by `witness_pha_completes_eku` is:

```text
Client / EKU initiator                  Server / EKU responder
Fin [N] ----------------------------->
                                        rx := N+1; tx := N+1
        X----------------------------- ACK of Fin [N+1]
        <----------------------------- CertificateRequest [N+1]
Record deprotected under N+1:
Fin treated as acknowledged; tx := N+1
Process CertificateRequest (context N+1)
PHA response [N+1] ------------------->
        <----------------------------- ACK of PHA response [N+1]
```

The other `witness_*_completes_eku` claims replace the CertificateRequest by a
NewConnectionId, application data, or a late ACK for Req. `witness_cid_old_epoch`
instead delivers the CID before EKU; the Fin retransmission then keeps epoch N
and uses the new CID. The full trails include duplicates, fragments, and
intermediate transitions beyond this abbreviated flow.

## Bounds and progress assumptions

- One EKU exchange, at most one PHA request, one EA request in each direction,
  one unsolicited server EA, and one server CID advertisement.
- 32 distinct record handles per endpoint; bounds are asserted and not wrapped.
  One record reference per ACK; arbitrary ACK-list packing is outside the model.
- Default drop budget 1, with at most two retries per transmitted handshake
  message. The two-loss profile and the separate two-loss run use a budget of 2.
- A single fixed two-fragment PHA request when enabled; arbitrary fragmentation,
  overlapping byte ranges, and PMTU changes are outside the model.
- Initial traffic epochs are 0, except for the epoch-three profile. Large epoch
  limits and counter overflow are not verified by the byte-sized abstraction.
- No concrete KDF, signature, MAC, certificate validation, active record forgery,
  or cross-connection binding proof. Every delivered record deprotects
  successfully; a new-epoch record that fails deprotection is not modeled.
- EA application delivery is assumed reliable and authenticated independently
  of the DTLS record network. EA objects are therefore not DTLS records in this
  model and do not trigger Step 7. Their wire encoding, transport loss recovery,
  and full application deadline policy are not verified.
- Old and newly issued CIDs remain routable. Full CID retirement, path migration,
  and arbitrary CID pools are not modeled.
- With one EKU exchange, the rule that no further EKU starts while a PHA
  exchange following an EKU is outstanding cannot be exercised.

Safety profiles also use independent endpoint retransmission opportunities.
With bounded retries, unfavorable scheduling can cause an explicit abort.
`no_deadlock` includes such a local abort and must not be read as successful
authentication. Records addressed to an aborted endpoint are drained/discarded
by the network model; a closed endpoint must not artificially block the other
endpoint's timeout processing.

Strict `successful_completion` profiles use `ROUND_TIMEOUTS=1`: SPIN's global
`timeout` schedules due retries at quiescence, and both endpoints receive their
retry opportunity before another round. Enabled normal processing precedes the
next round. This is an idealized processing/time assumption, not a guarantee
for arbitrary CPU delays, arbitrary independent timer schedules, or unbounded loss.
An explicitly expired EA context is an allowed operation failure in its own
profile; that result is not called successful authentication.

## Commands and verifier settings

```sh
./scripts/spin-check.sh regressions --output <dir>/final --seconds 600
./scripts/spin-check.sh all --output <dir>/final-cli --seconds 600
./scripts/spin-check.sh dtls --define DROPS=2 --define ROUND_TIMEOUTS=1 \
  --define ENABLE_PHA=1 --define PHA_TIMING=2 \
  --claim protocol_safety --claim successful_completion \
  --output <dir>/final-two --seconds 600
```

Generation/compilation and verification use the equivalent of:

```sh
spin -a <profile -D flags> <entry-point.pml>
gcc -O2 -DNOREDUCE -DMEMLIM=512 -DVECTORSZ=2048 -o pan pan.c
./pan -a -N <claim> -m20000 -w18 -b -n
```

All runs reported here use exact full-state storage, with partial-order reduction
disabled and no fairness option. Passing positive checks completed their search
without reaching the memory or depth limits. Expected counterexamples stop at
the first violation and are then replayed. The runner checks the search summary,
resource limits, expected error count, and witness/mutation evidence.

The runtime option `-b` makes reaching the depth bound an error. It does not
enable bitstate storage: that requires compilation with `-DBITSTATE`.
[SPIN verifier options](https://spinroot.com/spin/Man/Pan.html) document both.
Approximate manual exploration requires `--bitstate`; the regression suite
rejects that mode.

Compiling `pan.c` dominates the run time. The `--seconds` limit applies to each
generation, compilation, and verification command; the default of 120 can be
too short on a loaded machine.

The following deliberate depth-limit check must exit nonzero; it did:

```sh
./scripts/spin-check.sh dtls --claim protocol_safety --pan-args=-m1 \
  --output <dir>/final-depth --seconds 600
```

## Regression results

Positive columns list stored states for searches with zero errors. The last
column lists stored states at the expected counterexample. Profile names
beginning with `negative-` or `mutant-` deliberately require a violation.

| Profile | Positive claims: stored states | Expected counterexamples: stored states |
| --- | --- | --- |
| `dtls-base` | `protocol_safety`: 6450 | — |
| `dtls-pha-loss-safety` | `protocol_safety`: 103789 | — |
| `dtls-pha-loss` | `protocol_safety`: 141; `successful_completion`: 113 | `witness_pha_completes_eku`: 31 |
| `dtls-pha-two-losses` | `protocol_safety`: 321; `successful_completion`: 188 | `witness_pha_completes_eku`: 34 |
| `dtls-pha-fragments` | `protocol_safety`: 766; `successful_completion`: 644 | `witness_pha_completes_eku`: 38 |
| `dtls-pha-cid-fragments` | `protocol_safety`: 10072; `successful_completion`: 9023 | `witness_pha_completes_eku`: 47; `witness_cid_completes_eku`: 7203 |
| `dtls-epoch-three` | `protocol_safety`: 141; `successful_completion`: 113 | — |
| `dtls-pha-cross-flight` | `protocol_safety`: 789; `successful_completion`: 614 | — |
| `dtls-pha-cross-flight-loss` | `protocol_safety`: 4214; `successful_completion`: 2775 | — |
| `dtls-server-initiates-pha` | `protocol_safety`: 1960; `successful_completion`: 1245 | — |
| `dtls-other-ack` | `protocol_safety`: 115; `successful_completion`: 87 | `witness_other_ack_completes_eku`: 26 |
| `dtls-app-data` | `protocol_safety`: 3111; `successful_completion`: 2820 | `witness_app_completes_eku`: 1556 |
| `dtls-cid-immediate` | `protocol_safety`: 127; `successful_completion`: 99 | `witness_cid_completes_eku`: 28 |
| `dtls-cid-before-eku` | `protocol_safety`: 207; `successful_completion`: 177 | `witness_cid_old_epoch`: 33 |
| `dtls-cid-request` | `protocol_safety`: 161; `successful_completion`: 118 | — |
| `dtls-cid-spare` | `protocol_safety`: 127; `successful_completion`: 99 | — |
| `dtls-prior-handshake` | `protocol_safety`: 4986; `successful_completion`: 3201 | — |
| `dtls-ticket-ignore` | `protocol_safety`: 127; `successful_completion`: 99 | — |
| `dtls-ea-generations` | `protocol_safety`: 500; `successful_completion`: 378 | `witness_old_ea`: 32 |
| `dtls-ea-expiration` | `protocol_safety`: 516; `successful_completion`: 379 | `witness_expired_ea`: 32 |
| `dtls-ea-spontaneous` | `protocol_safety`: 2541; `successful_completion`: 1986 | — |
| `crossed-loss` | `protocol_safety`: 1583; `successful_completion`: 886 | — |
| `crossed-server-initiates-pha` | `protocol_safety`: 751; `successful_completion`: 533 | — |
| `crossed-client-wins-pha` | `protocol_safety`: 1119; `successful_completion`: 821 | `witness_pha_completes_eku`: 36 |
| `tls-crossed` | `protocol_safety`: 96; `successful_completion`: 75 | — |
| `tls-app` | `protocol_safety`: 596; `successful_completion`: 442 | — |
| `tls-pha` | `protocol_safety`: 107; `successful_completion`: 86 | — |
| `tls-server-initiates-pha` | `protocol_safety`: 88; `successful_completion`: 74 | — |
| `tls-ea` | `protocol_safety`: 293; `successful_completion`: 239 | `witness_old_ea`: 27 |
| `negative-message` | — | `no_unexpected`: 20 |
| `negative-ack-epoch` | — | `no_illegal_parameter`: 20 |
| `negative-group` | — | `no_illegal_parameter`: 20 |
| `mutant-old-epoch-record` | — | `protocol_safety`: 98 |
| `mutant-global-pha` | — | `successful_completion`: 26 |
| `mutant-early-pha` | — | `authentication_context`: 26 |
| `mutant-pha-transcript` | — | `authentication_context`: 28 |
| `mutant-current-exporter` | — | `authentication_context`: 31 |
| `mutant-cid-retention` | — | `successful_completion`: 39 |

The extra two-loss run stored 8244 states for safety and 4514 for strict completion, both with zero errors. The three default CLI modes
also passed `protocol_safety` and `no_deadlock` with zero errors.

## Exact profile definitions

Defaults and transport selection come from the hashed entry point and shared
model. The following are the complete additional `-D` definitions:

| Profile | Additional definitions |
| --- | --- |
| `dtls-base` | `DROPS=1` |
| `dtls-pha-loss-safety` | `INITIATE_A=1 INITIATE_B=0 DROPS=1 ENABLE_PHA=1 PHA_TIMING=2` |
| `dtls-pha-loss` | `INITIATE_A=1 INITIATE_B=0 ROUND_TIMEOUTS=1 DROPS=1 DROP_FIRST_FIN_ACK=1 ENABLE_PHA=1 PHA_TIMING=2` |
| `dtls-pha-two-losses` | `INITIATE_A=1 INITIATE_B=0 ROUND_TIMEOUTS=1 DROPS=2 DROP_FIRST_FIN_ACK=1 ENABLE_PHA=1 PHA_TIMING=2` |
| `dtls-pha-fragments` | `INITIATE_A=1 INITIATE_B=0 ROUND_TIMEOUTS=1 DROPS=1 DROP_FIRST_FIN_ACK=1 ENABLE_PHA=1 PHA_TIMING=2 FRAGMENT_PHA=1` |
| `dtls-pha-cid-fragments` | `INITIATE_A=1 INITIATE_B=0 ROUND_TIMEOUTS=1 DROPS=1 DROP_FIRST_FIN_ACK=1 ENABLE_PHA=1 PHA_TIMING=2 FRAGMENT_PHA=1 ENABLE_CID=1` |
| `dtls-epoch-three` | `INITIATE_A=1 INITIATE_B=0 ROUND_TIMEOUTS=1 DROPS=1 DROP_FIRST_FIN_ACK=1 ENABLE_PHA=1 PHA_TIMING=2 INIT_RX_I=3 INIT_TX_I=3 INIT_RX_R=3 INIT_TX_R=3` |
| `dtls-pha-cross-flight` | `INITIATE_A=1 INITIATE_B=0 DROPS=0 ENABLE_PHA=1 PHA_TIMING=1 ROUND_TIMEOUTS=1` |
| `dtls-pha-cross-flight-loss` | `INITIATE_A=1 INITIATE_B=0 DROPS=1 ENABLE_PHA=1 PHA_TIMING=1 ROUND_TIMEOUTS=1` |
| `dtls-server-initiates-pha` | `INITIATE_A=0 INITIATE_B=1 DROPS=1 ENABLE_PHA=1 PHA_TIMING=0 ROUND_TIMEOUTS=1` |
| `dtls-other-ack` | `INITIATE_A=1 INITIATE_B=0 ROUND_TIMEOUTS=1 DROPS=1 DROP_FIRST_FIN_ACK=1 EXTRA_REQUEST_ACK=1` |
| `dtls-app-data` | `INITIATE_A=1 INITIATE_B=0 ROUND_TIMEOUTS=1 DROPS=1 DROP_FIRST_FIN_ACK=1 APP_QUOTA=1` |
| `dtls-cid-immediate` | `INITIATE_A=1 INITIATE_B=0 ROUND_TIMEOUTS=1 DROPS=1 DROP_FIRST_FIN_ACK=1 ENABLE_CID=1` |
| `dtls-cid-before-eku` | `INITIATE_A=1 INITIATE_B=0 ROUND_TIMEOUTS=1 DROPS=1 DROP_FIRST_FIN_ACK=1 ENABLE_CID=1 CID_TIMING=1` |
| `dtls-cid-request` | `INITIATE_A=1 INITIATE_B=0 DROPS=0 ROUND_TIMEOUTS=1 ENABLE_CID=1 ENABLE_CID_REQUEST=1` |
| `dtls-cid-spare` | `INITIATE_A=1 INITIATE_B=0 ROUND_TIMEOUTS=1 DROPS=1 DROP_FIRST_FIN_ACK=1 ENABLE_CID=1 CID_IMMEDIATE=0` |
| `dtls-prior-handshake` | `DROPS=1 ROUND_TIMEOUTS=1 ENABLE_PRIOR_HS=1` |
| `dtls-ticket-ignore` | `INITIATE_A=1 INITIATE_B=0 ROUND_TIMEOUTS=1 DROPS=1 DROP_FIRST_FIN_ACK=1 ENABLE_TICKET=1` |
| `dtls-ea-generations` | `INITIATE_A=1 INITIATE_B=0 DROPS=0 ENABLE_EA=1 EA_DELAY_UNTIL_EKU=1 EA_SPONT_TRIGGER_B=0 ROUND_TIMEOUTS=1` |
| `dtls-ea-expiration` | `INITIATE_A=1 INITIATE_B=0 DROPS=0 ENABLE_EA=1 EA_DELAY_UNTIL_EKU=1 EA_SPONT_TRIGGER_B=0 ROUND_TIMEOUTS=1 EXPIRE_OLD_EXPORTER=1` |
| `dtls-ea-spontaneous` | `INITIATE_A=1 INITIATE_B=0 DROPS=0 ROUND_TIMEOUTS=1 ENABLE_EA=1` |
| `crossed-loss` | `DROPS=1 ROUND_TIMEOUTS=1` |
| `crossed-server-initiates-pha` | `DROPS=0 ROUND_TIMEOUTS=1 ENABLE_PHA=1 PHA_TIMING=2` |
| `crossed-client-wins-pha` | `KX_A=20 KX_B=10 DROPS=1 DROP_FIRST_FIN_ACK=1 ROUND_TIMEOUTS=1 ENABLE_PHA=1 PHA_TIMING=2` |
| `tls-crossed` | `(model defaults)` |
| `tls-app` | `APP_QUOTA=1` |
| `tls-pha` | `INITIATE_A=1 INITIATE_B=0 ENABLE_PHA=1` |
| `tls-server-initiates-pha` | `INITIATE_A=0 INITIATE_B=1 ENABLE_PHA=1` |
| `tls-ea` | `INITIATE_A=1 INITIATE_B=0 DROPS=0 ENABLE_EA=1 EA_DELAY_UNTIL_EKU=1 EA_SPONT_TRIGGER_B=0` |
| `negative-message` | `DROPS=0 INJECT_ERRORS=1` |
| `negative-ack-epoch` | `DROPS=0 INJECT_ERRORS=2` |
| `negative-group` | `DROPS=0 INJECT_ERRORS=3` |
| `mutant-old-epoch-record` | `INITIATE_A=1 INITIATE_B=0 DROPS=0 DEFER_RESP=1 FAULT_OLD_EPOCH_COMPLETES=1` |
| `mutant-global-pha` | `INITIATE_A=1 INITIATE_B=0 ROUND_TIMEOUTS=1 DROPS=2 DROP_FIRST_FIN_ACK=1 ENABLE_PHA=1 PHA_TIMING=2 FAULT_GLOBAL_PHA=1` |
| `mutant-early-pha` | `INITIATE_A=1 INITIATE_B=0 ROUND_TIMEOUTS=1 DROPS=1 DROP_FIRST_FIN_ACK=1 ENABLE_PHA=1 PHA_TIMING=2 FAULT_EARLY_PHA=1` |
| `mutant-pha-transcript` | `INITIATE_A=1 INITIATE_B=0 ROUND_TIMEOUTS=1 DROPS=1 DROP_FIRST_FIN_ACK=1 ENABLE_PHA=1 PHA_TIMING=2 FAULT_PHA_TRANSCRIPT=1` |
| `mutant-current-exporter` | `INITIATE_A=1 INITIATE_B=0 DROPS=0 ENABLE_EA=1 EA_DELAY_UNTIL_EKU=1 EA_SPONT_TRIGGER_B=0 ROUND_TIMEOUTS=1 FAULT_EA_CURRENT=1` |
| `mutant-cid-retention` | `INITIATE_A=1 INITIATE_B=0 ROUND_TIMEOUTS=1 DROPS=1 DROP_FIRST_FIN_ACK=1 ENABLE_CID=1 CID_TIMING=1 FAULT_CID_RETENTION=1` |

## Source hashes and local artifacts

| File | SHA-256 |
| --- | --- |
| `model/eku_protocol.pml` | `fc8ea15a231674f97ccfada97d8327e782ac51b1077d0ef596e8a767f4e8d815` |
| `model/extended_key_update.pml` | `ddc1df05484f5de352ea48280011ad7ccc64bce1d3e5d6be288a02328a458e9b` |
| `model/extended_key_update_crossed.pml` | `19ea373107cceded5784adedaa46bb0b96956ea91ad3b00e1400a658878af28b` |
| `model/tls13_extended_key_update.pml` | `aafa12776203543eb1d9af23ec8b6db12dd8811b8e5f087e249f41f9a62820e7` |
| `scripts/spin_verify.py` | `1ffe080da37bd4ff4d7724c99a0d846f748c2cea5469a874b874a9ce865a0a71` |
| `scripts/spin-check.sh` | `84c133fa16ba861fe363b8650cc1ac21c20a7970c23feb7882763a8e8f122e39` |
| `draft-ietf-tls-extended-key-update.md` | `220787d321ff96d44af470885995b53de9b7c62c87d91d00c122830d314b5e9e` |

Each run writes a `summary.json` with flags, hashes, tool versions and all
results to its output directory. Each profile directory contains the entry
point and shared source snapshots, generation/compile logs, verifier logs, and
replayed expected trails. These artifacts are local and are not part of the
repository; the source and runner allow the checks to be repeated without them.
