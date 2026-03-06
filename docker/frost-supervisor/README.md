# frost-supervisor

A minimal PID 1 process supervisor that runs `frostd` and `nginx` side by side.

## Why this exists

`frostd` unconditionally binds to `127.0.0.1` when `--no-tls-very-insecure` is set, regardless
of the `--ip` argument. This makes it unreachable from outside the local network namespace when
TLS is terminated externally.

Tracked upstream: [Feature request: allow binding to non-loopback address when TLS is terminated externally](https://github.com/ZcashFoundation/frost-tools/issues/586)

Until that is resolved, this supervisor runs `nginx` alongside `frostd` in the same network
namespace, proxying external traffic on `0.0.0.0:2744` to `frostd` on `127.0.0.1:12744`.
When the upstream fix lands this crate can be deleted and `frostd` can be run directly.

## Logging

All output is written to stderr, prefixed by process name:

```
[supervisor] starting frostd on 127.0.0.1:12744
[supervisor] starting nginx on 0.0.0.0:2744 -> 127.0.0.1:12744
[frostd] listening on 127.0.0.1:12744
[nginx] ...
```

To follow a single process:

```sh
# frostd only
<log-source> | grep '^\[frostd\]'

# nginx only
<log-source> | grep '^\[nginx\]'

# supervisor events only
<log-source> | grep '^\[supervisor\]'
```

## Behaviour

- Blocks in `sigwaitinfo` - no polling, wakes on `SIGCHLD`, `SIGTERM`, or `SIGINT`
- If either child exits for any reason, the supervisor terminates the other and exits
- On `SIGTERM`/`SIGINT`, sends `SIGTERM` to both children, waits up to 5 seconds, then `SIGKILL`
- Reaps all zombie children as PID 1
