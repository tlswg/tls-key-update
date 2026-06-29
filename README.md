# Extended Key Update for Transport Layer Security (TLS) 1.3

This is the working area for the IETF [TLS Working Group](https://datatracker.ietf.org/wg/tls/documents/) Internet-Draft, "Extended Key Update for Transport Layer Security (TLS) 1.3".

* [Editor's Copy](https://tlswg.github.io/tls-key-update/#go.draft-ietf-tls-extended-key-update.html)
* [Datatracker Page](https://datatracker.ietf.org/doc/draft-ietf-tls-extended-key-update)
* [Individual Draft](https://datatracker.ietf.org/doc/html/draft-ietf-tls-extended-key-update)
* [Compare Editor's Copy to Individual Draft](https://tlswg.github.io/tls-key-update/#go.draft-ietf-tls-extended-key-update.diff)


## Contributing

See the
[guidelines for contributions](https://github.com/tlswg/tls-key-update/blob/main/CONTRIBUTING.md).

Contributions can be made by creating pull requests.
The GitHub interface supports creating pull requests using the Edit (✏) button.


## Command Line Usage

Formatted text and HTML versions of the draft can be built using `make`.

```sh
$ make
```

Command line usage requires that you have the necessary software installed.  See
[the instructions](https://github.com/martinthomson/i-d-template/blob/main/doc/SETUP.md).

## SPIN Model Checks

The `model/` directory contains three PROMELA/SPIN models:

- `model/tls13_extended_key_update.pml`
  - TLS 1.3 EKU state machine (lower state-space, no DTLS ACK/retention path).
  - Primary checks: `no_unexpected`, `no_illegal_parameter`, `key_sync`.
  - Assumes all directional generation counters start at the same numeric
    generation `E`; `key_sync` compares sender and receiver per direction.
- `model/extended_key_update.pml`
  - DTLS EKU model with one initiator and one responder (no crossed requests).
  - Primary checks: `no_unexpected`, `no_illegal_parameter`, `epoch_consistency`.
- `model/extended_key_update_crossed.pml`
  - DTLS EKU with crossed requests, loss/reordering, retry bounds, and liveness stress.
  - Primary checks: `no_unexpected`, `no_illegal_parameter`, `epoch_consistency`, `no_deadlock`.

Detailed model/spec mapping and scope notes are documented in:

- `model/SPEC-MAPPING.md`

Running the model checks requires SPIN and a C compiler. On Debian/Ubuntu, they
can be installed with:

```sh
sudo apt-get install spin gcc
```

SPIN verification consists of three steps: generate `pan.c` from the Promela
model, compile `pan.c`, and run the resulting verifier. The repository script
performs these steps explicitly in a temporary directory:

```sh
spin -a model.pml
gcc -O2 -o pan pan.c
./pan -a -N property_name
```

To run verification in a separate `/tmp` working directory (to avoid generating
`pan.*` and other SPIN artifacts in the repo), use:

```sh
./scripts/spin-check.sh all
```

For larger state spaces (especially crossed requests), pass additional
`--define` values and `pan` options:

```sh
./scripts/spin-check.sh crossed --define DROPS=0 --pan-args "-m200000 -w18"
```

Alternatively, you can also execute the command individually:

```sh
repo=$(pwd)
work=$(mktemp -d /tmp/eku-spin.XXXXXX)

(cd "$work" && spin -search -ltl no_unexpected "$repo/model/tls13_extended_key_update.pml")
(cd "$work" && spin -search -ltl no_illegal_parameter "$repo/model/tls13_extended_key_update.pml")
(cd "$work" && spin -search -ltl key_sync "$repo/model/tls13_extended_key_update.pml")
(cd "$work" && spin -search -ltl no_unexpected "$repo/model/extended_key_update.pml")
(cd "$work" && spin -search -ltl no_illegal_parameter "$repo/model/extended_key_update.pml")
(cd "$work" && spin -search -ltl epoch_consistency "$repo/model/extended_key_update.pml")
(cd "$work" && spin -search -ltl no_unexpected "$repo/model/extended_key_update_crossed.pml")
(cd "$work" && spin -search -ltl no_illegal_parameter "$repo/model/extended_key_update_crossed.pml")
(cd "$work" && spin -search -ltl epoch_consistency "$repo/model/extended_key_update_crossed.pml")
(cd "$work" && spin -search -ltl no_deadlock "$repo/model/extended_key_update_crossed.pml")
```

The `spin -search` form automatically generates and compiles the verifier
before running it; no separate compilation command is needed for these
individual commands. Run the block from the repository root so that
`repo=$(pwd)` points to the correct directory.

For larger state spaces (especially crossed requests), use smaller or larger
compile-time bounds directly with `spin -D...`:

```sh
(cd "$work" && spin -DDROPS=0 -DREQ_RETRIES=1 -DFIN_RETRIES=1 -search -ltl no_unexpected "$repo/model/extended_key_update_crossed.pml")
```

Optional paths can be enabled with `-DDEFER_RESP=1` for DTLS deferred
responses and `-DINJECT_ERRORS=1` for negative-message injection. The negative
input configuration is expected to violate the corresponding safety claim.
