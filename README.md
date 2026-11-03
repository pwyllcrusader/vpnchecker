# vpnchecker

[Русская версия](README.ru.md)

A VPN kill switch for macOS, built for GlobalProtect (works with any VPN that creates a `utunN` interface). It guarantees that **Claude and Cursor reach the internet only through the VPN**, and can optionally restrict the whole machine the same way.

| `mode` | What happens while the VPN is down |
|---|---|
| `scoped` (default) | Only Claude and Cursor are affected. Everything else, including GlobalProtect reconnects, captive portals and split-tunnel traffic, keeps working. |
| `full` | Additionally **all** outbound traffic is blocked except the VPN client itself (portal / gateways) and the local network. |

Claude / Cursor protection is **always on**, in both modes. It has three layers, so no single one has to be perfect:

1. **Freeze** – every Claude / Cursor process and all its children (MCP servers, terminals, extension hosts) is frozen with `SIGSTOP` (or killed) the moment the VPN drops, and resumed when the VPN is verified again. A frozen app cannot send anything.
2. **DNS shield** – lookups for `anthropic.com`, `claude.ai`, `claude.com`, `cursor.sh`, `cursor.com` are answered by a local responder through per-domain resolver files in `/etc/resolver`. The query never leaves the Mac, so the ISP / router never sees which AI service you were about to use.
3. **Kernel block** – a [pf](https://man.openbsd.org/pf.conf) rule refuses the known Claude / Cursor server addresses on every interface except the tunnel. Unlike the freeze it has no reaction window: it also covers the first packets after wake-up, before the daemon has run.

## How it works

The daemon runs as a root launchd daemon, starts at boot and is restarted if it exits. It reacts to kernel routing / address / interface changes (`PF_ROUTE` socket) within milliseconds and polls every `check.interval` as a fallback.

**VPN state.** The VPN is up when an interface matching `interface_pattern` has an address from `vpn.subnets` **and** the default route goes through it (GlobalProtect keeps `utunN` with a pool address after disconnect, so the interface alone is not enough) **and** GlobalProtect does not report a disconnected tunnel. GlobalProtect's own state is read from the root-owned settings plist (`tunnel-status`, current gateway and tunnel address); only an explicit "disconnected" counts, so an unknown value can never freeze your apps by itself.

**Sleep / wake.** While the Mac sleeps nothing runs, and right after wake GlobalProtect may still show a dead tunnel as up. The daemon notices the clock jump (`protect.wake_gap`), freezes first, keeps the apps frozen for at least `protect.wake_hold`, and resumes only after the VPN passed `protect.resume_checks` consecutive checks spread over a minimum time. Every wake therefore costs a short pause even when the VPN is fine. The kernel block (layer 3) covers the few hundred milliseconds before the daemon's first check.

**Gateway auto-discovery.** The daemon learns VPN gateways from four sources so GlobalProtect can always reconnect, also to a **new** gateway after a reconnect (relevant in `full` mode and for keeping gateways out of the protected set):

- the gateway GlobalProtect reports for its current connection (root-owned plist; no DNS needed, the address is allowed the moment it changes);
- the portal and gateway host names from GlobalProtect's settings and `pan_gp_event.log`, re-resolved every `resolve_interval`, right after the VPN drops, and whenever GlobalProtect reports a different gateway;
- host routes the kernel installs for the gateway outside the tunnel (`allow.learn_gateways`);
- `allow.domains` / `allow.cidrs` you add yourself. Each domain covers **all its subdomains**: the daemon runs a DNS forwarder on `127.0.0.1:10053` and writes `/etc/resolver/<domain>` for each entry, so every lookup under it goes through the forwarder and the answer's addresses enter the pf allow table *before* the answer reaches the app. Upstream is taken from `scutil --dns` per query (VPN split DNS keeps working).

Every address is kept for `resolve_retain` and persisted in `/var/db/vpnchecker/cache.json`. Host names found only in the user-writable event log are trusted only if they end in one of `allow.gateway_suffixes` (default `gpcloudservice.com`), or equal a portal or the gateway GlobalProtect reports itself.

**`full` mode rules** (anchor `com.apple/vpnchecker`; the stock `/etc/pf.conf` already evaluates `com.apple/*`, so system config is not modified):

```
pass out quick on lo0 all
pass out quick on utun4 all keep state (if-bound)           # the tunnel
pass out quick proto { tcp udp } to any port 53 keep state  # DNS (system resolver)
pass out quick proto udp to any port { 67 68 123 546 547 } keep state
pass out quick inet6 proto icmp6 all keep state
pass out quick to <vpnchecker_allow> keep state             # VPN portal/gateways, LAN
block return out quick all
```

**`scoped` mode rules:**

```
table <vpnchecker_protected> persist { …Claude / Cursor server addresses… }
pass out quick on utun4 to <vpnchecker_protected> keep state (if-bound)
block return out quick to <vpnchecker_protected>
```

**Surviving its own exit.** On `SIGTERM` / `SIGINT` the daemon leaves rules that pass only traffic *sourced from `vpn.subnets`*, frozen apps stay frozen and the DNS shield stays up; launchd restarts the daemon, and `vpnchecker stop` releases everything. On a crash or `SIGKILL` the last loaded rules stay in pf.

## Requirements

- macOS (Apple Silicon or Intel)
- `sudo` for installation (pf, `/etc/resolver` and signalling other users' processes require root)

## Installation

Connect the VPN, then:

```sh
curl -fsSL https://github.com/pwyllcrusader/vpnchecker/releases/latest/download/install.sh | sh
```

The script downloads the prebuilt universal binary from the latest GitHub release, verifies its checksum, creates `~/.config/vpnchecker/config.yaml` if missing, refuses to continue if the VPN is not detected (it would cut the internet), runs `sudo vpnchecker install` and links `/usr/local/bin/vpnchecker`. Run the same command to update. If the VPN pool is not `10.0.0.0/8`, set `vpn.subnets` in the config and run it again.

### From source

```sh
cargo install vpnchecker      # or from a checkout: cargo install --path .

# 1. Create the config and set vpn.subnets (see Configuration)
vpnchecker config init
$EDITOR ~/.config/vpnchecker/config.yaml
vpnchecker config validate

# 2. Check detection with the VPN connected
vpnchecker diagnose
vpnchecker procs        # the Claude / Cursor processes that will be frozen

# 3. Install as a launchd daemon
sudo "$(which vpnchecker)" install
vpnchecker status
```

`install` copies the **running** binary to `/Library/PrivilegedHelperTools/vpnchecker` (owned by `root:wheel`, so a regular user cannot swap it), writes `/Library/LaunchDaemons/com.vpnchecker.daemon.plist` and starts the daemon. It starts on boot and is restarted if it exits. Use the full path with `sudo` — sudo has its own `PATH`. Re-run `install` after every upgrade.

## Commands

| Command | Root | Description |
|---|---|---|
| `install` / `uninstall` | yes | Install / remove the launchd daemon (`uninstall` also removes pf rules, resumes frozen apps and removes the DNS shield) |
| `start` / `restart` | yes | Start / restart the installed daemon |
| `stop [--keep-block]` | yes | Stop the daemon, remove its pf rules (`--keep-block` keeps the exit rules), resume frozen apps, remove the DNS shield |
| `flush` | yes | Remove vpnchecker pf rules immediately |
| `status [--json]` | no | VPN state, GlobalProtect gateway, mode, protection state, frozen processes, DNS shield |
| `check [-q]` | no | Check the VPN once. Exit code: `0` up, `1` down, `2` error |
| `procs` | no | List the Claude / Cursor processes covered (STAT `T` = frozen) |
| `diagnose` | no | Interfaces, checks, GlobalProtect connection, protected servers, resolved allowlist domains, learned gateways |
| `reload` | owner | Reload the config in the running daemon (same as `SIGHUP`) |
| `allow <domain\|URL>` | owner | Add a domain (with subdomains) to `allow.domains` in the config, keeping comments, and reload the daemon |
| `logs [-f] [-n N]` | no | Show `/var/log/vpnchecker.log` |
| `config init [--force]` / `validate` / `path` | no | Manage the config file |
| `run [--dry-run]` | yes (no with `--dry-run`) | Run in the foreground. `--dry-run` logs rules and what would be frozen instead of doing it |

Global options: `--config <path>` (env `VPNCHECKER_CONFIG`), `--socket <path>` (default `/var/run/vpnchecker.sock`), `-v`/`-vv`.

## Configuration

Path: `~/.config/vpnchecker/config.yaml`. Unknown fields are rejected. Full annotated example: [config.example.yaml](config.example.yaml).

```yaml
mode: scoped                    # scoped | full

vpn:
  interface_pattern: '^(utun\d+|gpd\d+)$'
  subnets: [10.4.0.0/16]        # VPN address pool, required
  check_globalprotect: true

protect:                        # Claude / Cursor, always active
  action: stop                  # stop (freeze) | kill
  dns_shield: true
  pf_block: true
  observe_connections: false
  extra_process_patterns: []    # add your own regexes
  wake_gap: 3s
  wake_hold: 5s
  resume_checks: 4
```

Everything under `protect` has a default covering Claude.app, Claude Code (`claude`), Cursor.app, `cursor-agent`, their extensions and every child process; run `vpnchecker procs` to see what matches on your machine.

**`vpn.subnets`:** the address pool the VPN assigns. Look at the `utunN` address with the VPN connected (`ifconfig`); GlobalProtect hands out a different address each time, so use the whole pool (e.g. `10.4.0.0/16`), not one address.

**What to put into `allow`:** for the VPN itself with GlobalProtect usually nothing. It matters in `full` mode: the VPN client must be able to reconnect (other VPN clients, an identity provider used for SAML login), and services that should keep working without the VPN go there too, with all their subdomains: `vpnchecker allow telegram.org`. A domain cannot be in `allow.domains` and `protect.domains` at the same time.

## Verification

```sh
vpnchecker status
vpnchecker procs
sudo pfctl -a com.apple/vpnchecker -sr     # rules are always loaded, with or without the VPN
ls /etc/resolver                           # allow.domains always (forwarder); while the VPN is down also anthropic.com, claude.ai, cursor.sh, ... (shield)
```

Disconnect GlobalProtect: Claude and Cursor freeze within a fraction of a second (`vpnchecker procs` shows STAT `T`), `vpnchecker status` shows `Blocked`. Reconnect: after a second or two they resume. Closing and opening the laptop lid does the same, with a pause of about `wake_hold`.

## Troubleshooting

- **Claude / Cursor stay frozen although the VPN is up** — `vpnchecker status` and `vpnchecker check` show which check fails (usually `vpn.subnets` does not contain the tunnel address, or GlobalProtect reports a state containing "disconnect"). Fix the config and `vpnchecker reload`, or `sudo vpnchecker stop` to release everything.
- **After a crash apps are still frozen** — `sudo vpnchecker stop`, or `sudo pkill -CONT -f 'Claude.app|Cursor.app'`.
- **A protected domain does not resolve although the VPN is up** — the shield files are removed when the VPN is verified; `sudo vpnchecker stop` removes them at once (`ls /etc/resolver` shows files starting with `# managed by vpnchecker`). vpnchecker never touches resolver files it did not write.
- **`full` mode: the VPN does not reconnect while blocked** — the client needs an address that is not allowlisted (new gateway, IdP for SAML). Run `sudo vpnchecker stop`, connect, run `vpnchecker diagnose` to find the host, add it to `allow`, `sudo vpnchecker start`. Consider `scoped` mode, which never touches the VPN client's traffic.
- **Captive portals** (hotels, airports) — in `scoped` mode the login page just works (only Claude / Cursor are held back). In `full` mode: `sudo vpnchecker stop`, log in, `sudo vpnchecker start`.
- **Daemon does not start** — `vpnchecker logs`. An `unknown field` error means the installed binary is older than the config: reinstall with `sudo "$(which vpnchecker)" install`.
- **Uninstall** — `sudo vpnchecker uninstall` removes the daemon, plist, binary, pf rules and DNS shield, resumes frozen apps and releases the pf token.

## Claude Code hook (optional)

The freeze already stops Claude Code; a hook gives a clear message instead of a hang. In `~/.claude/settings.json`:

```json
{
  "hooks": {
    "UserPromptSubmit": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "vpnchecker check -q || { echo 'VPN is down, request blocked by vpnchecker' >&2; exit 2; }"
          }
        ]
      }
    ]
  }
}
```

## Limitations

- **Process-level protection is not a firewall.** Between a VPN drop and the freeze there are tens of milliseconds (routing event, process scan, signal); the kernel block closes that gap only for the known server addresses. A new, never-seen Claude / Cursor address, or a process the patterns do not match, is covered only by the freeze (or not at all, for unmatched processes).
- **The kernel block is destination-based, not per-process.** While the VPN is down, every app on the Mac is refused the Claude / Cursor server addresses; shared CDN addresses (e.g. Cloudflare for `api3.cursor.sh`) may make a few unrelated sites unreachable. `observe_connections` widens this (GitHub etc.), which is why it is off by default.
- **The DNS shield blocks the protected domains for every app** (a browser cannot open `claude.ai` while the VPN is down). Cached answers may still be served, but no query leaves the Mac, and the frozen apps make no connections. It works for programs that use the system resolver (`getaddrinfo`); a program with its own DNS client or DNS-over-HTTPS bypasses it, which the freeze and the kernel block still cover.
- **Apps with their own DNS** (DoH, hardcoded resolvers) bypass `/etc/resolver`: subdomains of allowed domains they look up are not learned and stay blocked in `full` mode.
- **No protection before the daemon starts after boot**, and none while it is stopped.
- **`full` mode:** blocks traffic that the VPN routes outside the tunnel (split-tunnel exclusions) and captive portals; DNS (port 53) is allowed to any server, so lookups of other domains go to the local resolver while the VPN is down.
- **Trust:** the daemon is root and reads a user-owned config and the user-writable GlobalProtect event log. The config holds only patterns, host names, subnets and timings (host names are validated strictly because they become file names), but a user who can edit it can make the daemon freeze arbitrary processes. Log-derived hosts are filtered by `gateway_suffixes`.
- First start with the VPN down and an empty cache has no kernel block yet (nothing learned); the freeze and DNS shield still apply.

## Development

```sh
cargo test
cargo clippy --all-targets
vpnchecker --socket ./vc.sock run --dry-run -v    # needs no root, shows what would be frozen
```

Tests cover the state machine (`guard`), process selection and real SIGSTOP / SIGCONT on a child process, the DNS responder over real UDP, pf rule rendering, GlobalProtect plist parsing and config validation.

Release: bump `version` in `Cargo.toml`, commit, `git tag vX.Y.Z && git push --tags`. The `release` workflow builds the universal binary and publishes it with `install.sh` to GitHub Releases.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at your option.
