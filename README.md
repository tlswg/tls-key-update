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
  - Primary checks: `no_unexpected`, `key_sync`.
- `model/extended_key_update.pml`
  - DTLS EKU model with one initiator and one responder (no crossed requests).
  - Primary checks: `no_unexpected`, `epoch_consistency`.
- `model/extended_key_update_crossed.pml`
  - DTLS EKU with crossed requests, loss/reordering, retry bounds, and liveness stress.
  - Primary checks: `no_unexpected`, `epoch_consistency`, `no_deadlock`.

Detailed model/spec mapping and scope notes are documented in:

- `model/SPEC-MAPPING.md`

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
