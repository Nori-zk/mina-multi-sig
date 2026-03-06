#!/bin/bash
set -uo pipefail   # no -e: we attempt all images and report at the end

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

log()     { echo "[release-all] $*"; }
section() { echo; echo "== $* =="; }
success() { echo "[release-all] ok: $*"; }
warn()    { echo "[release-all] warn: $*" >&2; }
die()     { echo "[release-all] ERROR: $*" >&2; exit 1; }

usage() {
  echo "Usage: $0 <frostd-commitish-sha>"
  echo
  echo "  frostd-commitish-sha   Full commit SHA of github.com/ZcashFoundation/frost-tools"
  exit 1
}

[[ $# -eq 0 || "$1" == "--help" || "$1" == "-h" ]] && usage

FROSTD_COMMITISH="$1"
[[ "$FROSTD_COMMITISH" == "main" ]] && die "must be a commit SHA, not a branch name"

REGISTRY="${REGISTRY:-0x6a6f6e6e79}" # Change 0x6a6f6e6e79 to your own docker registry user/org
CRATE_VERSION=$(grep -oP '(?<=^version = ").*(?=")' "$REPO_ROOT/mina-frost-client/Cargo.toml") \
  || die "Could not read version from mina-frost-client/Cargo.toml"

CLIENT_VERSION="${FROSTD_COMMITISH}-${CRATE_VERSION}"
SERVER_VERSION="${FROSTD_COMMITISH}"

section "Release Configuration"
log "Registry:       ${REGISTRY}"
log "Client version: ${CLIENT_VERSION}"
log "Server version: ${SERVER_VERSION}"

# --- Upfront image check ---

section "Checking local images"

IMAGES=(
  "frost-mina-client:${CLIENT_VERSION}"
  "frost-mina-client-mesa:${CLIENT_VERSION}"
  "frost-server:${SERVER_VERSION}"
)

SKIP=()
RELEASE=()

for entry in "${IMAGES[@]}"; do
  name="${entry%%:*}"
  version="${entry##*:}"
  full="${REGISTRY}/${name}"
  missing=0
  for arch in amd64 arm64; do
    if ! docker image inspect "${full}:${version}-${arch}" >/dev/null 2>&1; then
      warn "${full}:${version}-${arch} not found locally -- skipping ${name}"
      missing=1
      break
    fi
  done
  if [[ $missing -eq 0 ]]; then
    log "  found ${full}:${version} (amd64 + arm64)"
    RELEASE+=("$entry")
  else
    SKIP+=("$name")
  fi
done

[[ ${#RELEASE[@]} -eq 0 ]] && die "No images available to release. Run build-all.sh first."

# --- Release ---

RELEASED=()
FAILED=()

release_image() {
  local name="$1"
  local version="$2"
  local full="${REGISTRY}/${name}"

  section "${name}:${version}"

  (
    set -e
    log "Pushing ${full}:${version}-amd64"
    docker push "${full}:${version}-amd64"

    log "Pushing ${full}:${version}-arm64"
    docker push "${full}:${version}-arm64"

    log "Creating multi-arch manifest ${full}:${version}"
    docker buildx imagetools create \
      --tag "${full}:${version}" \
      "${full}:${version}-amd64" \
      "${full}:${version}-arm64"

    log "Tagging ${full}:latest"
    docker buildx imagetools create \
      --tag "${full}:latest" \
      "${full}:${version}-amd64" \
      "${full}:${version}-arm64"
  )
  if [[ $? -eq 0 ]]; then
    success "${name}:${version}"
    RELEASED+=("${full}:${version}" "${full}:latest")
  else
    warn "${name}:${version} release failed"
    FAILED+=("${name}")
  fi
}

for entry in "${RELEASE[@]}"; do
  release_image "${entry%%:*}" "${entry##*:}"
done

# --- Summary ---

section "Summary"

if [[ ${#RELEASED[@]} -gt 0 ]]; then
  log "Released:"
  for img in "${RELEASED[@]}"; do log "  $img"; done
fi

if [[ ${#SKIP[@]} -gt 0 ]]; then
  log "Skipped (images not built):"
  for img in "${SKIP[@]}"; do log "  $img"; done
fi

if [[ ${#FAILED[@]} -gt 0 ]]; then
  log "Failed:"
  for img in "${FAILED[@]}"; do log "  $img"; done
  exit 1
fi
