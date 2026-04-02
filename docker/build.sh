#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# --- Helpers ---

log()     { echo "[build] $*"; }
section() { echo; echo "== $* =="; }
success() { echo "[build] ok: $*"; }
die()     { echo "[build] ERROR: $*" >&2; exit 1; }

usage() {
  echo "Usage: $0 --name <image-name> --file <Dockerfile> [--features <cargo-features>] [--frostd-ref <git-ref>]"
  echo
  echo "  --name         Image name (e.g. frost-mina-client)"
  echo "  --file         Dockerfile to use (e.g. Dockerfile.client)"
  echo "  --features     Cargo feature flags to enable (optional)"
  echo "  --frostd-ref   Full commit SHA of github.com/ZcashFoundation/frost-tools (required)"
  exit 1
}

# --- Argument parsing ---

IMAGE_NAME=""
DOCKERFILE=""
FEATURES=""
FROSTD_COMMITISH=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --name)        IMAGE_NAME="$2";   shift 2 ;;
    --file)        DOCKERFILE="$2";   shift 2 ;;
    --features)    FEATURES="$2";     shift 2 ;;
    --frostd-ref)  FROSTD_COMMITISH="$2";   shift 2 ;;
    --help|-h)     usage ;;
    *) die "Unknown argument: $1" ;;
  esac
done

[[ -z "$IMAGE_NAME" ]] && die "--name is required"
[[ -z "$DOCKERFILE" ]] && die "--file is required"
[[ -z "$FROSTD_COMMITISH" ]] && die "--frostd-ref is required (must be a full commit SHA)"
[[ "$FROSTD_COMMITISH" == "main" ]] && die "--frostd-ref must be a commit SHA, not a branch name"

DOCKERFILE_PATH="$SCRIPT_DIR/$DOCKERFILE"
[[ -f "$DOCKERFILE_PATH" ]] || die "Dockerfile not found: $DOCKERFILE_PATH"

# --- Config ---

REGISTRY="${REGISTRY:-0x6a6f6e6e79}" # Change 0x6a6f6e6e79 to your own docker registry user/org
FULL_IMAGE="${REGISTRY}/${IMAGE_NAME}"
CRATE_VERSION=$(grep -oP '(?<=^version = ").*(?=")' "$REPO_ROOT/mina-frost-client/Cargo.toml") \
  || die "Could not read version from mina-frost-client/Cargo.toml"

# Tagging convention (frostd = github.com/ZcashFoundation/frost-tools):
#   frost-mina-client:<frostd-commitish>-<mina-multi-sig-crate-version>-<arch>
#   e.g. frost-mina-client:a1b2c3d4e5f6-0.2.0-amd64
#
#   frost-server:<frostd-commitish>-<arch>
#   e.g. frost-server:a1b2c3d4e5f6-amd64
if [[ "$DOCKERFILE" == "Dockerfile.server" ]]; then
  VERSION="${FROSTD_COMMITISH}"
elif [[ "$DOCKERFILE" == "Dockerfile.client" ]]; then
  VERSION="${FROSTD_COMMITISH}-${CRATE_VERSION}"
else
  VERSION="${CRATE_VERSION}"
fi

TEMP_BUILDER="multiarch-builder-$$"
CURRENT_BUILDER="$(docker buildx ls 2>/dev/null | awk '/\*/{print $1; exit}' || true)"

# --- Summary ---

section "Build Configuration"
log "Image:      ${FULL_IMAGE}"
log "Version:    ${VERSION}"
log "Dockerfile: ${DOCKERFILE}"
log "Features:   ${FEATURES:-<none>}"
log "frostd ref: ${FROSTD_COMMITISH}"
log "Platforms:  linux/amd64, linux/arm64"

# --- Build args ---

BUILD_ARGS=(
  "--build-arg" "FEATURES=${FEATURES}"
  "--build-arg" "FROSTD_COMMITISH=${FROSTD_COMMITISH}"
)

# --- Cleanup ---

cleanup() {
  rc=$?
  section "Cleanup"
  if [[ -n "$CURRENT_BUILDER" ]]; then
    log "Restoring previous buildx builder: $CURRENT_BUILDER"
    docker buildx use "$CURRENT_BUILDER" >/dev/null 2>&1 || true
  else
    docker buildx use default >/dev/null 2>&1 || true
  fi
  log "Removing temporary builder: $TEMP_BUILDER"
  docker buildx rm "$TEMP_BUILDER" >/dev/null 2>&1 || true
  exit $rc
}

trap cleanup EXIT INT TERM

# --- Setup ---

section "QEMU Setup"
log "Registering QEMU handlers (needed for arm64 runtime stages)..."
docker run --rm --privileged multiarch/qemu-user-static --reset -p yes >/dev/null 2>&1 || true
success "QEMU ready"

section "Buildx Setup"
log "Creating temporary builder: $TEMP_BUILDER"
docker buildx create --name "$TEMP_BUILDER" --driver docker-container --use
log "Bootstrapping builder..."
docker buildx inspect --bootstrap >/dev/null
success "Builder ready"

# --- Build ---

section "Building linux/amd64"
docker buildx build \
  --platform linux/amd64 \
  --file "$DOCKERFILE_PATH" \
  "${BUILD_ARGS[@]}" \
  --tag "${FULL_IMAGE}:${VERSION}-amd64" \
  --output type=docker \
  "$REPO_ROOT"
success "Tagged: ${FULL_IMAGE}:${VERSION}-amd64"

section "Building linux/arm64"
docker buildx build \
  --platform linux/arm64 \
  --file "$DOCKERFILE_PATH" \
  "${BUILD_ARGS[@]}" \
  --tag "${FULL_IMAGE}:${VERSION}-arm64" \
  --output type=docker \
  "$REPO_ROOT"
success "Tagged: ${FULL_IMAGE}:${VERSION}-arm64"

# --- Done ---

section "Done"
success "Built images:"
log "  ${FULL_IMAGE}:${VERSION}-amd64"
log "  ${FULL_IMAGE}:${VERSION}-arm64"
