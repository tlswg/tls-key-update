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

The `model/` directory contains three PROMELA/SPIN entry points. All three
include the shared protocol model in
[`model/eku_protocol.pml`](model/eku_protocol.pml):

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

The verification scripts have different roles:

- [`scripts/spin-check.sh`](scripts/spin-check.sh) is the command-line entry
  point. It forwards its arguments to the Python runner.
- [`scripts/spin_verify.py`](scripts/spin_verify.py) implements the verification
  workflow: it snapshots the model sources, generates and compiles the verifier,
  runs the selected properties, and checks the results. It also defines the
  regression profiles and replays expected counterexamples.

The Python runner checks SPIN's `errors:` summary and rejects incomplete searches
or exhausted memory/depth limits; a zero process exit status alone is not treated
as a successful verification. No external Python packages are required.

Detailed model/spec mapping, assumptions, and recorded verification results are
available in [model/SPEC-MAPPING.md](model/SPEC-MAPPING.md) and
[model/VERIFICATION.md](model/VERIFICATION.md).

Running the model checks requires Python 3, SPIN, and GCC. On Debian/Ubuntu, they
can be installed with:

```sh
sudo apt-get install python3 spin gcc
```

SPIN verification consists of three steps: generate `pan.c` from the Promela
model, compile `pan.c`, and run the resulting verifier. The repository script
performs these steps explicitly in a temporary directory:

```sh
spin -a model.pml
gcc -O2 -DNOREDUCE -DMEMLIM=512 -DVECTORSZ=2048 -o pan pan.c
./pan -a -N property_name
```

To run verification in a separate `/tmp` working directory (to avoid generating
`pan.*` and other SPIN artifacts in the repo), use:

```sh
./scripts/spin-check.sh all
```

`all` checks `protocol_safety` and `no_deadlock` for each entry point using
the default model parameters. `no_deadlock` allows bounded-retry aborts;
it does not establish successful completion of every authentication operation.

To run the predefined regression suite, including PHA, EA, CID handling,
fragmentation, reachability witnesses, and deliberately faulty variants, use:

```sh
./scripts/spin-check.sh regressions --output /tmp/eku-spin-results
```

Individual profiles can be selected, for example:

```sh
./scripts/spin-check.sh regressions --profile dtls-pha-loss
```

Some regression claims intentionally require a counterexample: they establish
that a target sequence is reachable or that a faulty variant is detected.
The runner checks that expectation and replays the resulting trail. Strict
completion profiles use the explicit timeout assumptions documented in
`model/SPEC-MAPPING.md`.

The shell wrapper and the Python runner accept the same arguments. For example,
`python3 scripts/spin_verify.py all` is equivalent to the first command above.
Available options can be listed with:

```sh
python3 scripts/spin_verify.py --help
```

The runner prints its artifact directory and retains source snapshots, logs,
trails, per-profile results, and a `summary.json` with source hashes and tool
versions. Searches use exact full-state storage with partial-order reduction
disabled by default. `--bitstate` explicitly selects approximate exploration
for manual runs and is not allowed for the regression suite.

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

Optional paths can be enabled with `-DDEFER_RESP=1` for acknowledging a DTLS
request before sending the response. Negative-message injection uses
`-DINJECT_ERRORS=1` for an invalid message, `2` for an invalid ACK epoch, or
`3` for a wrong negotiated group. These configurations are expected to violate
the corresponding safety claim.
