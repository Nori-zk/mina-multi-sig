#!/bin/bash
set -uo pipefail   # no -e: we attempt all builds and report at the end

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD="$SCRIPT_DIR/build.sh"

log()     { echo "[build-all] $*"; }
section() { echo; echo "== $* =="; }
die()     { echo "[build-all] ERROR: $*" >&2; exit 1; }

usage() {
  echo "Usage: $0 <frostd-commitish-sha>"
  echo
  echo "  frostd-commitish-sha   Full commit SHA of github.com/ZcashFoundation/frost-tools"
  exit 1
}

[[ $# -eq 0 || "$1" == "--help" || "$1" == "-h" ]] && usage

FROSTD_COMMITISH="$1"
[[ "$FROSTD_COMMITISH" == "main" ]] && die "must be a commit SHA, not a branch name"

BUILT=()
FAILED=()

run_build() {
  local label="$1"; shift
  section "$label"
  if bash "$BUILD" "$@"; then
    log "built: $label"
    BUILT+=("$label")
  else
    log "failed: $label"
    FAILED+=("$label")
  fi
}

run_build "frost-mina-client" \
  --name "frost-mina-client" \
  --file "Dockerfile.client" \
  --frostd-ref "$FROSTD_COMMITISH"

run_build "frost-mina-client-mesa" \
  --name "frost-mina-client-mesa" \
  --file "Dockerfile.client" \
  --features "mesa" \
  --frostd-ref "$FROSTD_COMMITISH"

run_build "frost-server" \
  --name "frost-server" \
  --file "Dockerfile.server" \
  --frostd-ref "$FROSTD_COMMITISH"

section "Summary"
if [[ ${#BUILT[@]} -gt 0 ]]; then
  log "Built:  ${BUILT[*]}"
fi
if [[ ${#FAILED[@]} -gt 0 ]]; then
  log "Failed: ${FAILED[*]}"
  exit 1
fi
