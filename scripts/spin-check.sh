#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Run SPIN checks in a separate /tmp working directory (avoids polluting the repo
and reduces the chance of IDE crashes from large pan builds).

Usage:
  scripts/spin-check.sh <tls|dtls|crossed|all> [--exhaustive] [--keep-tmp]
                       [--pan-args "<args>"] [--spin-args "<args>"]
                       [--define NAME=VALUE]...

Examples:
  scripts/spin-check.sh tls
  scripts/spin-check.sh dtls --define DROPS=0 --pan-args "-m200000 -w18"
  scripts/spin-check.sh crossed --pan-args "-m200000 -w18"   # may be large
  scripts/spin-check.sh crossed --exhaustive                 # full search (very large)

Notes:
  - By default, the crossed-requests DTLS model runs in bitstate mode (-b) to
    keep memory usage down. Use --exhaustive to disable bitstate.
  - --define values are passed as spin -DNAME=VALUE (can be repeated).
EOF
}

root_dir() {
  cd "$(dirname "${BASH_SOURCE[0]}")/.." >/dev/null 2>&1
  pwd
}

mode="${1:-}"
shift || true

if [[ -z "${mode}" || "${mode}" == "-h" || "${mode}" == "--help" ]]; then
  usage
  exit 0
fi

keep_tmp=0
exhaustive=0
pan_args=()
spin_args=()
defines=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --keep-tmp)
      keep_tmp=1
      shift
      ;;
    --exhaustive)
      exhaustive=1
      shift
      ;;
    --pan-args)
      pan_args+=($2)
      shift 2
      ;;
    --spin-args)
      spin_args+=($2)
      shift 2
      ;;
    --define)
      defines+=("$2")
      shift 2
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

ROOT="$(root_dir)"

run_one() {
  local name="$1"
  local model_rel="$2"
  local -a claims=()
  shift 2
  claims=("$@")

  local model="${ROOT}/${model_rel}"
  if [[ ! -f "${model}" ]]; then
    echo "Model not found: ${model}" >&2
    exit 1
  fi

  local tmp
  tmp="$(mktemp -d "/tmp/tls-eks-spin-${name}.XXXXXX")"
  echo "==> ${name}: ${model_rel}"
  echo "    tmp: ${tmp}"

  (
    cd "${tmp}"

    local -a dflags=()
    for d in "${defines[@]}"; do
      dflags+=("-D${d}")
    done

    spin -a "${spin_args[@]}" "${dflags[@]}" "${model}"
    gcc -O2 -o pan pan.c

    local -a local_pan_args=()
    if [[ "${name}" == "crossed" && "${exhaustive}" -eq 0 ]]; then
      local_pan_args+=("-b")
    fi

    if [[ ${#pan_args[@]} -gt 0 ]]; then
      # shellcheck disable=SC2206
      local_pan_args+=(${pan_args[*]})
    fi

    for claim in "${claims[@]}"; do
      echo "    pan: ${claim}"
      ./pan -a -N "${claim}" "${local_pan_args[@]}"
    done
  )

  if [[ "${keep_tmp}" -eq 1 ]]; then
    echo "    (kept tmp dir)"
  else
    rm -rf "${tmp}"
  fi
}

run_tls() {
  run_one tls model/tls13_extended_key_update.pml no_unexpected key_sync
}

run_dtls() {
  run_one dtls model/extended_key_update.pml no_unexpected epoch_consistency
}

run_crossed() {
  run_one crossed model/extended_key_update_crossed.pml no_unexpected epoch_consistency no_deadlock
}

case "${mode}" in
  tls) run_tls ;;
  dtls) run_dtls ;;
  crossed) run_crossed ;;
  all)
    run_tls
    run_dtls
    run_crossed
    ;;
  *)
    echo "Unknown mode: ${mode}" >&2
    usage >&2
    exit 2
    ;;
esac
