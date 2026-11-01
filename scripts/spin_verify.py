#!/usr/bin/env python3
"""Bounded exact SPIN verification and counterexample-based regression checks."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
MODELS = {
    "tls": "tls13_extended_key_update.pml",
    "dtls": "extended_key_update.pml",
    "crossed": "extended_key_update_crossed.pml",
}


def invoke(command, directory, log, limit=120):
    with log.open("w") as output:
        process = subprocess.run(command, cwd=directory, stdout=output,
                                 stderr=subprocess.STDOUT, timeout=limit)
    return process.returncode, log.read_text(errors="replace")


def verify(name, mode, defines, claims, directory, pan_args=(), spin_args=(),
           bitstate=False, mutations=(), seconds=120):
    directory.mkdir(parents=True, exist_ok=True)
    # A self-contained source snapshot allows replay after the checkout changes.
    for filename in (MODELS[mode], "eku_protocol.pml"):
        shutil.copy2(ROOT / "model" / filename, directory / filename)
    source = directory / MODELS[mode]
    flags = [f"-D{x}" for x in defines]
    result = {"profile": name, "mode": mode, "defines": defines, "claims": [],
              "exact": not bitstate, "directory": str(directory)}
    result["source_sha256"] = {
        filename: hashlib.sha256((directory / filename).read_bytes()).hexdigest()
        for filename in (MODELS[mode], "eku_protocol.pml")
    }
    generate = ["spin", "-a", *spin_args, *flags, source.name]
    code, output = invoke(generate, directory, directory / "generate.log", seconds)
    if code or "syntax error" in output or "Error:" in output:
        raise RuntimeError(f"{name}: SPIN generation failed; see {directory / 'generate.log'}")
    compile_command = ["gcc", "-O2", "-DNOREDUCE", "-DMEMLIM=512", "-DVECTORSZ=2048"]
    if bitstate:
        compile_command.append("-DBITSTATE")
    compile_command.extend(["-o", "pan", "pan.c"])
    code, _ = invoke(compile_command, directory, directory / "compile.log", seconds)
    if code:
        raise RuntimeError(f"{name}: compilation failed; see {directory / 'compile.log'}")
    result["commands"] = {"generate": generate, "compile": compile_command}
    for claim, expect_error in claims:
        started = time.monotonic()
        command = ["./pan", "-a", "-N", claim, "-m20000", "-w18", "-b", "-n", *pan_args]
        log = directory / f"{claim}.log"
        code, output = invoke(command, directory, log, seconds)
        counts = re.search(r"depth reached\s+(\d+), errors:\s*(\d+)", output)
        states = re.search(r"([\d.e+]+) states, stored", output)
        resource_failure = any(marker in output.lower() for marker in (
            "max search depth too small", "out of memory", "reached -dmemlim",
            "vectorsz is too small", "cannot allocate", "depth limit reached"))
        if not counts or resource_failure:
            raise RuntimeError(f"{name}/{claim}: incomplete or failed verification; see {log}")
        errors = int(counts[2])
        if expect_error:
            passed = errors == 1 and code == 0 and "Search not completed" in output
            # A witness must fail its never claim, rather than an unrelated assertion.
            if claim.startswith("witness_"):
                passed &= "assertion violated" in output
            trail = directory / f"{source.name}.trail"
            if not trail.exists():
                passed = False
            else:
                saved_trail = directory / f"{claim}.trail"
                trail.replace(saved_trail)
                replay = ["spin", "-t", "-p", "-g", *flags, "-k", saved_trail.name, source.name]
                replay_code, replay_text = invoke(replay, directory, directory / f"{claim}.replay.log", seconds)
                passed &= replay_code == 0 and "trail ends after" in replay_text
                if claim.startswith("witness_"):
                    passed &= "spin: _spin_nvr.tmp:" in replay_text
                if claim in mutations:
                    passed &= "acceptance cycle" in output or "assertion violated" in output
                if name == "mutant-any-ack":
                    passed &= all(item in replay_text for item in (
                        "peer[0].done = 1", "peer[0].finish_ack_received = 0", "wrong_ack_seen = 1"))
                if name in ("mutant-early-pha", "mutant-pha-transcript"):
                    passed &= "pha_context_ok = 0" in replay_text
                if name == "mutant-current-exporter":
                    passed &= "ea_context_ok = 0" in replay_text
                if name == "mutant-global-pha":
                    passed &= "finish_ack_lost = 1" in replay_text and "peer[0].pha_buffered = 1" in replay_text
        else:
            passed = errors == 0 and code == 0 and "Search not completed" not in output
        entry = {"claim": claim, "expected_counterexample": expect_error,
                 "passed": bool(passed), "errors": errors, "depth": int(counts[1]),
                 "states": states[1] if states else None,
                 "seconds": round(time.monotonic() - started, 3)}
        result["claims"].append(entry)
        print(f"{'PASS' if passed else 'FAIL'} {name}/{claim}: errors={errors}, states={entry['states']}", flush=True)
        (directory / "result.json").write_text(json.dumps(result, indent=2) + "\n")
        if not passed:
            raise RuntimeError(f"unexpected verification result: {name}/{claim}; see {log}")
    return result


def suite_profiles():
    safety = [("protocol_safety", False)]
    progress = safety + [("successful_completion", False)]
    single = ["INITIATE_A=1", "INITIATE_B=0"]
    round_loss = single + ["ROUND_TIMEOUTS=1", "DROPS=1", "DROP_FIRST_FIN_ACK=1"]
    pha = round_loss + ["ENABLE_PHA=1", "PHA_TIMING=2"]
    ack = round_loss + ["EXTRA_REQUEST_ACK=1"]
    ea = single + ["DROPS=0", "ENABLE_EA=1", "EA_DELAY_UNTIL_EKU=1", "EA_SPONT_TRIGGER_B=0"]
    return [
        ("dtls-base", "dtls", ["DROPS=1"], safety),
        ("dtls-pha-loss-safety", "dtls", single + ["DROPS=1", "ENABLE_PHA=1", "PHA_TIMING=2"], safety),
        ("dtls-pha-loss", "dtls", pha, progress + [("witness_pha_ack_loss", True)]),
        ("dtls-pha-fragments", "dtls", pha + ["FRAGMENT_PHA=1"], progress + [("witness_pha_ack_loss", True)]),
        ("dtls-pha-cid-fragments", "dtls", pha + ["FRAGMENT_PHA=1", "ENABLE_CID=1"], progress + [("witness_pha_ack_loss", True), ("witness_cid_old_epoch", True)]),
        ("dtls-epoch-three", "dtls", pha + ["INIT_RX_I=3", "INIT_TX_I=3", "INIT_RX_R=3", "INIT_TX_R=3"], progress),
        ("dtls-pha-cross-flight", "dtls", single + ["DROPS=0", "ENABLE_PHA=1", "PHA_TIMING=1", "ROUND_TIMEOUTS=1"], progress),
        ("dtls-ack-association", "dtls", ack, progress + [("witness_wrong_ack", True)]),
        ("dtls-cid-immediate", "dtls", round_loss + ["ENABLE_CID=1"], progress + [("witness_cid_old_epoch", True)]),
        ("dtls-cid-request", "dtls", single + ["DROPS=0", "ROUND_TIMEOUTS=1", "ENABLE_CID=1", "ENABLE_CID_REQUEST=1"], progress),
        ("dtls-cid-spare", "dtls", round_loss + ["ENABLE_CID=1", "CID_IMMEDIATE=0"], progress),
        ("dtls-prior-handshake", "dtls", ["DROPS=1", "ROUND_TIMEOUTS=1", "ENABLE_PRIOR_HS=1"], progress),
        ("dtls-ticket-ignore", "dtls", round_loss + ["ENABLE_TICKET=1"], progress),
        ("dtls-ea-generations", "dtls", ea + ["ROUND_TIMEOUTS=1"], progress + [("witness_old_ea", True)]),
        ("dtls-ea-expiration", "dtls", ea + ["ROUND_TIMEOUTS=1", "EXPIRE_OLD_EXPORTER=1"], progress + [("witness_expired_ea", True)]),
        ("dtls-ea-spontaneous", "dtls", single + ["DROPS=0", "ROUND_TIMEOUTS=1", "ENABLE_EA=1"], progress),
        ("crossed-loss", "crossed", ["DROPS=1", "ROUND_TIMEOUTS=1"], progress),
        ("crossed-server-initiates-pha", "crossed", ["DROPS=0", "ROUND_TIMEOUTS=1", "ENABLE_PHA=1", "PHA_TIMING=2"], progress),
        ("crossed-client-wins-pha", "crossed", ["KX_A=20", "KX_B=10", "DROPS=1", "DROP_FIRST_FIN_ACK=1", "ROUND_TIMEOUTS=1", "ENABLE_PHA=1", "PHA_TIMING=2"], progress + [("witness_pha_ack_loss", True)]),
        ("tls-crossed", "tls", [], progress),
        ("tls-app", "tls", ["APP_QUOTA=1"], progress),
        ("tls-pha", "tls", single + ["ENABLE_PHA=1"], progress),
        ("tls-ea", "tls", ea, progress + [("witness_old_ea", True)]),
        ("negative-message", "dtls", ["DROPS=0", "INJECT_ERRORS=1"], [("no_unexpected", True)]),
        ("negative-ack-epoch", "dtls", ["DROPS=0", "INJECT_ERRORS=2"], [("no_illegal_parameter", True)]),
        ("negative-group", "dtls", ["DROPS=0", "INJECT_ERRORS=3"], [("no_illegal_parameter", True)]),
        ("mutant-any-ack", "dtls", ack + ["FAULT_ANY_ACK=1"], [("protocol_safety", True)]),
        ("mutant-global-pha", "dtls", pha + ["FAULT_GLOBAL_PHA=1"], [("successful_completion", True)]),
        ("mutant-early-pha", "dtls", pha + ["FAULT_EARLY_PHA=1"], [("authentication_context", True)]),
        ("mutant-pha-transcript", "dtls", pha + ["FAULT_PHA_TRANSCRIPT=1"], [("authentication_context", True)]),
        ("mutant-current-exporter", "dtls", ea + ["ROUND_TIMEOUTS=1", "FAULT_EA_CURRENT=1"], [("authentication_context", True)]),
        ("mutant-cid-retention", "dtls", round_loss + ["ENABLE_CID=1", "FAULT_CID_RETENTION=1"], [("successful_completion", True)]),
    ]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=[*MODELS, "all", "regressions"])
    parser.add_argument("--define", action="append", default=[])
    parser.add_argument("--claim", action="append")
    parser.add_argument("--profile", action="append", help="Select named regression profiles")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--keep-tmp", action="store_true")
    parser.add_argument("--exhaustive", action="store_true", help="Compatibility option: exact search is already the default")
    parser.add_argument("--bitstate", action="store_true", help="Approximate exploration; never an exhaustive proof")
    parser.add_argument("--pan-args", default="")
    parser.add_argument("--spin-args", default="")
    parser.add_argument("--seconds", type=int, default=120, help="Per-command timeout")
    args = parser.parse_args()
    if args.mode == "regressions" and args.bitstate:
        parser.error("regressions require exact search")
    output = args.output.resolve() if args.output else Path(tempfile.mkdtemp(prefix="tls-eku-spin-"))
    output.mkdir(parents=True, exist_ok=True)
    print(f"Verification artifacts: {output}", flush=True)
    results = []
    try:
        if args.mode == "regressions":
            profiles = suite_profiles()
            if args.profile:
                unknown = set(args.profile) - {p[0] for p in profiles}
                if unknown:
                    parser.error(f"Unknown profiles: {', '.join(sorted(unknown))}")
                profiles = [p for p in profiles if p[0] in args.profile]
        else:
            modes = MODELS if args.mode == "all" else [args.mode]
            names = args.claim or ["protocol_safety", "no_deadlock"]
            profiles = [(mode, mode, [], [(claim, False) for claim in names]) for mode in modes]
        for name, mode, defines, claims in profiles:
            results.append(verify(name, mode, defines + args.define, claims, output / name,
                                  shlex.split(args.pan_args), shlex.split(args.spin_args),
                                  args.bitstate, [c for c, expected in claims if expected], args.seconds))
        summary = {"spin": subprocess.check_output(["spin", "-V"], text=True).strip(),
                   "gcc": subprocess.check_output(["gcc", "--version"], text=True).splitlines()[0],
                   "profiles": results}
        (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
        print(f"Completed {len(results)} profiles; summary: {output / 'summary.json'}", flush=True)
    except (RuntimeError, subprocess.TimeoutExpired) as error:
        print(str(error), flush=True)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
