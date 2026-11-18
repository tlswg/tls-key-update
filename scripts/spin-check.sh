#!/usr/bin/env bash
set -euo pipefail

# Exact verification is the default. The Python runner checks SPIN's result
# summary and resource limits, and preserves source snapshots and trails.
eku_script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "${eku_script_dir}/spin_verify.py" "$@"
