#!/bin/bash
set -uo pipefail   # no -e: we collect failures and report at the end

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

COMPOSE_SERVER="docker compose -f $SCRIPT_DIR/docker-compose.server.local.yml"
COMPOSE_CLIENT="docker compose -f $SCRIPT_DIR/docker-compose.client.local.yml"
COMPOSE_CLIENT_MESA="docker compose -f $SCRIPT_DIR/docker-compose.client-mesa.local.yml"

log()     { echo "[test] $*"; }
section() { echo; echo "== $* =="; }
pass()    { echo "[test] ok: $*"; }
fail()    { echo "[test] FAIL: $*" >&2; }
die()     { echo "[test] ERROR: $*" >&2; exit 1; }

usage() {
  echo "Usage: $0 <frostd-commitish-sha>"
  echo
  echo "  frostd-commitish-sha   Full commit SHA of github.com/ZcashFoundation/frost-tools"
  exit 1
}

[[ $# -eq 0 || "$1" == "--help" || "$1" == "-h" ]] && usage

FROSTD_COMMITISH="$1"
[[ "$FROSTD_COMMITISH" == "main" ]] && die "must be a commit SHA, not a branch name"

export FROSTD_COMMITISH

FAILURES=()

# --- Test: server ---

section "server"

server_cleanup() { $COMPOSE_SERVER down --remove-orphans >/dev/null 2>&1 || true; }

(
  set -e
  $COMPOSE_SERVER build server
  $COMPOSE_SERVER up -d server

  log "waiting for port 2744..."
  deadline=$(( $(date +%s) + 30 ))
  until bash -c 'echo > /dev/tcp/127.0.0.1/2744' 2>/dev/null; do
    [[ $(date +%s) -gt $deadline ]] && echo "timed out waiting for port 2744" >&2 && exit 1
    sleep 0.5
  done

  log "waiting for frostd to respond over nginx..."
  deadline=$(( $(date +%s) + 30 ))
  response="000"
  until [[ "$response" != "000" ]]; do
    [[ $(date +%s) -gt $deadline ]] && echo "timed out waiting for frostd HTTP response" >&2 && exit 1
    response=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 http://127.0.0.1:2744/ || true)
    sleep 0.5
  done
  log "frostd responded with HTTP $response"
)
if [[ $? -eq 0 ]]; then pass "server"; else fail "server"; FAILURES+=("server"); fi
server_cleanup

# --- Test: client ---

section "client"

(
  set -e
  $COMPOSE_CLIENT build client
  $COMPOSE_CLIENT run --rm --no-TTY client --help >/dev/null
)
if [[ $? -eq 0 ]]; then pass "client"; else fail "client"; FAILURES+=("client"); fi
$COMPOSE_CLIENT down --remove-orphans >/dev/null 2>&1 || true

# --- Test: client-mesa ---

section "client-mesa"

(
  set -e
  $COMPOSE_CLIENT_MESA build client-mesa
  $COMPOSE_CLIENT_MESA run --rm --no-TTY client-mesa --help >/dev/null
)
if [[ $? -eq 0 ]]; then pass "client-mesa"; else fail "client-mesa"; FAILURES+=("client-mesa"); fi
$COMPOSE_CLIENT_MESA down --remove-orphans >/dev/null 2>&1 || true

# --- Summary ---

section "Results"
if [[ ${#FAILURES[@]} -eq 0 ]]; then
  log "all tests passed"
else
  log "failed: ${FAILURES[*]}"
  exit 1
fi
