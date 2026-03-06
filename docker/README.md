# Docker

Build and test infrastructure for `frost-mina-client` and `frost-server`.

## Images

| Image | Description |
|---|---|
| `frost-mina-client` | CLI signing client |
| `frost-mina-client-mesa` | CLI signing client with the `mesa` feature flag (not yet implemented) |
| `frost-server` | `frostd` coordination server behind an nginx TCP proxy |

## Getting the frostd commit SHA

All images are pinned to a specific commit of [frost-tools](https://github.com/ZcashFoundation/frost-tools) (upstream has no release tags). Get the current HEAD SHA:

```sh
git ls-remote https://github.com/ZcashFoundation/frost-tools.git HEAD
```

Copy the full 40-character SHA - branch names are rejected.

## Workflow

```
test-local.sh  ->  build-all.sh  ->  release-all.sh
```

### 1. Test locally

Builds and smoke-tests all images on the local platform before committing to a full multi-platform
build:

```sh
./test-local.sh <frostd-commitish-sha>
```

Each image is tested in isolation - a failure in one does not abort the others. Results are
summarised at the end. `client-mesa` will fail until the `mesa` feature flag is implemented in
`mina-frost-client`. Do not proceed to build if `server` or `client` fail.

### 2. Build

Builds all images for both platforms (linux/amd64, linux/arm64) and tags them locally:

```sh
./build-all.sh <frostd-commitish-sha>
```

The registry defaults to `0x6a6f6e6e79`. Override with `REGISTRY=<your-registry>`.

Each image is attempted independently. If one fails (e.g. `frost-mina-client-mesa` while `mesa`
is not yet implemented) the others continue. The summary at the end shows what built and what
failed. The script exits non-zero if anything failed.

### 3. Release

Pushes arch-specific images and creates multi-arch manifests on the registry:

```sh
./release-all.sh <frostd-commitish-sha>
```

Before pushing anything, `release-all.sh` checks that both arch images (`-amd64`, `-arm64`) exist
locally for each image. Any image with a missing arch is skipped with a warning - the rest are
still released. This means a partial build (e.g. without mesa) produces a partial release without
blocking the images that did build. The summary at the end lists what was released, what was
skipped, and what failed.

Each image is released under two multi-arch manifests: the versioned tag and `latest`. For example,
`frost-server:<sha>` and `frost-server:latest` both point to the same amd64+arm64 images.

## Swarm deployment with auto TLS/SSL

The `docker-compose.server.swarm.yml` deploys `frost-server` behind [caddy-docker-proxy](https://github.com/lucaslorentz/caddy-docker-proxy), which automatically provisions and renews Let's Encrypt certificates.

### First-time setup (once per cluster)

```sh
# 1. Initialise the swarm manager
./swarm/init-swarm.sh

# 2. Create the overlay networks
./swarm/create-networks.sh
```

### Configure

Edit `docker-compose.server.swarm.yml`:
- Replace `frost.example.com` with your real domain.
- Replace `example@email.com` under `caddy.email` with a real address - Let's Encrypt uses this for certificate expiry notifications.

### Point DNS at the swarm manager

Create an A record for your domain pointing to the public IP address of the swarm manager node.
Caddy provisions certificates automatically - ensure the DNS record resolves to the correct IP.

### Deploy

```sh
./swarm/up.sh
```

### Tear down

```sh
./swarm/down.sh
```

## Using the client

Start a shell inside the container, mounting a local directory so the config persists between runs:

```sh
# Standard client
docker run --rm -it \
  -v "$HOME/.local/frost:/root/.local/frost" \
  0x6a6f6e6e79/frost-mina-client:latest \
  bash

# Mesa variant (once the mesa feature is implemented)
docker run --rm -it \
  -v "$HOME/.local/frost:/root/.local/frost" \
  0x6a6f6e6e79/frost-mina-client-mesa:latest \
  bash
```

All commands below are run inside that shell. The server URL is whatever domain you configured in
the swarm compose - caddy terminates TLS on 443 so no port is needed (e.g. `https://<your-domain>`).

### Typical workflow

```sh
# 1. Initialise - generates your communication key pair (once per participant)
mina-frost-client init -c ~/.frost/alice.toml

# 2. Export your contact and share it with the other participants out of band
mina-frost-client export -n alice -c ~/.frost/alice.toml

# 3. Import each other participant's contact string
mina-frost-client import <contact-string> -c ~/.frost/alice.toml

# 4. Distributed key generation
#    Coordinator (one participant) passes -S with the other participants' public keys:
mina-frost-client dkg -c ~/.frost/alice.toml -d "2-of-3 group" -s https://<your-domain> -t 2 -S <BOB_PUBKEY>,<EVE_PUBKEY>
#    All other participants join without -S:
mina-frost-client dkg -c ~/.frost/bob.toml  -d "2-of-3 group" -s https://<your-domain> -t 2

# 5. Note the group public key
mina-frost-client groups -c ~/.frost/alice.toml

# 6. Sign - coordinator starts the session
mina-frost-client coordinator -c ~/.frost/alice.toml -g <GROUP_PUBKEY> -S <BOB_PUBKEY>,<EVE_PUBKEY> -m tx.json -o signed-tx.json -n testnet

# 7. Sign - each other participant joins
mina-frost-client participant -c ~/.frost/bob.toml -g <GROUP_PUBKEY> -y

# 8. Build and broadcast the signed transaction
mina-frost-client graphql-build -i signed-tx.json -o broadcast.graphql
mina-frost-client graphql-broadcast -g broadcast.graphql -e https://api.minascan.io/node/devnet/v1/graphql
```

See [SIGNING-WORKFLOW.md](../SIGNING-WORKFLOW.md) for the full workflow including transaction preparation.

> **Note:** Distributing the client via Docker is a temporary approach. Ideally the client binary
> would be published as a pre-built artifact (e.g. GitHub Releases) so participants can run it
> directly without Docker.

## Temporary: nginx sidecar workaround

`frostd` unconditionally binds to `127.0.0.1` when `--no-tls-very-insecure` is set, making it
unreachable from outside the container. Until upstream resolves this
([#586](https://github.com/ZcashFoundation/frost-tools/issues/586)), the server image runs `nginx`
as a TCP proxy (`0.0.0.0:2744` -> `127.0.0.1:12744`) alongside `frostd` under a minimal Rust PID 1
supervisor. See [frost-supervisor/README.md](frost-supervisor/README.md) for details.

All output is prefixed by process name so individual processes can be isolated:

```sh
# all logs
docker logs <container>

# frostd only
docker logs <container> 2>&1 | grep '^\[frostd\]'

# nginx only
docker logs <container> 2>&1 | grep '^\[nginx\]'

# supervisor events only
docker logs <container> 2>&1 | grep '^\[supervisor\]'
```

Once [#586](https://github.com/ZcashFoundation/frost-tools/issues/586) is resolved,
[frost-supervisor/](frost-supervisor/) and [nginx.conf](nginx.conf) can be deleted and `frostd`
run directly. [Dockerfile.server](Dockerfile.server) will need updating at that point.

# Note to auditors

This folder covers distribution infrastructure only - build scripts, Dockerfiles, and runtime
configuration. It contains no signing logic, key material, or protocol code. The nginx sidecar
and frost-supervisor crate are a temporary workaround for an upstream limitation and will be
removed once resolved. This folder is not in scope for a security audit of the signing system.