# vpnchecker

[Русская версия](README.ru.md)

A VPN kill switch for macOS, built for GlobalProtect (works with any VPN that creates a `utunN` interface). It guarantees that **Claude, Cursor and Rider reach the internet only through the VPN**, and by default restricts the whole machine the same way (`mode: full`); `mode: scoped` limits it to those three apps.

| `mode` | What happens while the VPN is down |
|---|---|
| `scoped` | Only Claude, Cursor and Rider are affected. Everything else, including GlobalProtect reconnects, captive portals and split-tunnel traffic, keeps working. |
| `full` (default) | Additionally **all** outbound traffic is blocked except the VPN client itself (portal / gateways) and the local network. |

Claude / Cursor / Rider protection is **always on**, in both modes. It has three layers, so no single one has to be perfect:

1. **Freeze** – every Claude / Cursor / Rider process and all its children (MCP servers, terminals, extension hosts) is frozen with `SIGSTOP` (or killed) the moment the VPN drops, and resumed when the VPN is verified again. A frozen app cannot send anything. Always on in `scoped` mode. In `full` mode pf already blocks everything outside the tunnel, so the freeze is off unless you set `protect.freeze: true`.
2. **DNS shield** – lookups for `anthropic.com`, `claude.ai`, `claude.com`, `cursor.sh`, `cursor.com` are answered by a local responder through per-domain resolver files in `/etc/resolver`. The query never leaves the Mac, so the ISP / router never sees which AI service you were about to use.
3. **Kernel block** – a [pf](https://man.openbsd.org/pf.conf) rule refuses the known Claude / Cursor server addresses on every interface except the tunnel. Unlike the freeze it has no reaction window: it also covers the first packets after wake-up, before the daemon has run.

Layers 2 and 3 know only the Claude / Cursor servers. Rider (JetBrains) is protected by the freeze alone in `scoped` mode (and by the full block in `full` mode): it is an IDE that talks to your own repositories and services, so none of its hosts are shielded or blocked by default. Add them to `protect.domains` / `protect.hosts` if you want that.

## How it works

The daemon runs as a root launchd daemon, starts at boot and is restarted if it exits. It reacts to kernel routing / address / interface changes (`PF_ROUTE` socket) within milliseconds and polls every `check.interval` as a fallback.

**VPN state.** The VPN is up when an interface matching `interface_pattern` has an address from `vpn.subnets` **and** the default route goes through it (GlobalProtect keeps `utunN` with a pool address after disconnect, so the interface alone is not enough) **and** GlobalProtect does not report a disconnected tunnel. GlobalProtect's own state is read from the root-owned settings plist (`tunnel-status`, current gateway and tunnel address); only an explicit "disconnected" counts, so an unknown value can never freeze your apps by itself.

**Sleep / wake.** While the Mac sleeps nothing runs, and right after wake GlobalProtect may still show a dead tunnel as up. The daemon notices the clock jump (`protect.wake_gap`), blocks first (and, when the freeze is on, freezes the apps), keeps them blocked for at least `protect.wake_hold`, and resumes only after the VPN passed `protect.resume_checks` consecutive checks spread over a minimum time. With the freeze on, every wake therefore costs a short pause even when the VPN is fine. The kernel block (layer 3) covers the few hundred milliseconds before the daemon's first check.

**Gateway auto-discovery.** The daemon learns VPN gateways from five sources so GlobalProtect can always reconnect, also to a **new** gateway after a reconnect (relevant in `full` mode and for keeping gateways out of the protected set):

- the gateway GlobalProtect reports for its current connection (root-owned plist; no DNS needed, the address is allowed the moment it changes);
- the portal and gateway host names from GlobalProtect's settings and `pan_gp_event.log`, re-resolved every `resolve_interval`, right after the VPN drops, and whenever GlobalProtect reports a different gateway;
- host routes the kernel installs for the gateway outside the tunnel (`allow.learn_gateways`);
- in `full` mode, every lookup under `allow.gateway_suffixes` (default `gpcloudservice.com`) and for `allow.probe_hosts` (default `captive.apple.com`, `clients3.google.com` and `www.msftconnecttest.com`, the three hosts of GlobalProtect's captive-portal test) goes through the DNS forwarder, so the exact address the VPN client receives is allowed before it connects. This covers gateways the client has never used, rotating addresses, and the probe: GlobalProtect takes two refused probes for a captive portal and then waits instead of connecting;
- `allow.domains` / `allow.cidrs` you add yourself. Each domain covers **all its subdomains**: the daemon runs a DNS forwarder on `127.0.0.1:10053` and writes `/etc/resolver/<domain>` for each entry, so every lookup under it goes through the forwarder and the answer's addresses enter the pf allow table *before* the answer reaches the app. Upstream is taken from `scutil --dns` per query (VPN split DNS keeps working).

Every address is kept for `resolve_retain` and persisted in `/var/db/vpnchecker/cache.json`. Host names found only in the user-writable event log are trusted only if they end in one of `allow.gateway_suffixes` (default `gpcloudservice.com`), or equal a portal or the gateway GlobalProtect reports itself.

**`full` mode rules** (anchor `com.apple/vpnchecker`; the stock `/etc/pf.conf` already evaluates `com.apple/*`, so system config is not modified):

```
pass out quick on lo0 all flags any no state                # localhost, stateless on purpose
pass out quick on utun4 all keep state (if-bound)           # the tunnel
pass out quick proto { tcp udp } to any port 53 keep state  # DNS (system resolver)
pass out quick proto udp to any port { 67 68 123 546 547 } keep state
pass out quick inet6 proto icmp6 all keep state
pass out quick to <vpnchecker_allow> keep state             # VPN portal/gateways, LAN
block return out quick all
```

The loopback rule carries no state because on `lo0` a reply leaves "out" too. A stateful rule there matches only the first packet of a TCP connection, and the reply would be reset by the final block: that is every local TCP connection, including the GlobalProtect window talking to its own service on `127.0.0.1:4767`.

**`scoped` mode rules:**

```
table <vpnchecker_protected> persist { …Claude / Cursor server addresses… }
pass out quick on utun4 to <vpnchecker_protected> keep state (if-bound)
block return out quick to <vpnchecker_protected>
```

**Surviving its own exit.** On `SIGTERM` / `SIGINT` the daemon leaves rules that pass only traffic *sourced from `vpn.subnets`*, frozen apps stay frozen and the DNS shield stays up; launchd restarts the daemon, and `vpnchecker stop` releases everything. On a crash or `SIGKILL` the last loaded rules stay in pf.

**Updates.** With `update.auto: true` (default) the installed daemon looks at this repository's GitHub releases every `update.interval` (24h), and only while the VPN is verified up, so the download leaves through the tunnel and the restart never happens while the apps are blocked. When it finds a newer one it **asks first** (`update.confirm: true`, default): a dialog in your session offers *Update*, *Later* (asked again after `update.interval`) and *Skip This Version* (not asked again until a newer release appears). Nothing is downloaded without a yes; an unanswered dialog closes after five minutes and counts as later, and with nobody logged in nothing is installed. `update.confirm: false` installs unattended. After a yes, the release is downloaded into a root-only directory, checked against the release's SHA-256 file, has to report the announced version and has to accept the current config. Only then does it replace the binary, by rename; the daemon exits like on `SIGTERM`, leaving its exit rules in place, and launchd starts the new version within seconds. Pre-release tags are ignored and it never downgrades. `update.auto: false` turns it off; `sudo vpnchecker update` updates on demand and `vpnchecker update --check` only reports.

## Requirements

- macOS (Apple Silicon or Intel)
- `sudo` for installation (pf, `/etc/resolver` and signalling other users' processes require root)

## Installation

Connect the VPN, then:

```sh
curl -fsSL https://github.com/pwyllcrusader/vpnchecker/releases/latest/download/install.sh | sh
```

To restrict only Claude / Cursor / Rider and leave the rest of the Mac alone, pass the mode through to the script:

```sh
curl -fsSL https://github.com/pwyllcrusader/vpnchecker/releases/latest/download/install.sh | sh -s -- --mode scoped
```

The script downloads the prebuilt universal binary from the latest GitHub release, verifies its checksum, creates `~/.config/vpnchecker/config.yaml` if missing, refuses to continue if the VPN is not detected (it would cut the internet), runs `sudo vpnchecker install` and links `/usr/local/bin/vpnchecker`. `--mode scoped|full` (or `VPNCHECKER_MODE`) sets `mode` in the config, also when the config already exists; without it a new config starts in `full`. From then on the daemon offers new releases by itself (see **Updates** above); `sudo vpnchecker update` or the same command updates at once. If the VPN pool is not `10.0.0.0/8`, set `vpn.subnets` in the config and run it again.

### From source

```sh
cargo install vpnchecker      # or from a checkout: cargo install --path .

# 1. Create the config and set vpn.subnets (see Configuration)
vpnchecker config init
$EDITOR ~/.config/vpnchecker/config.yaml
vpnchecker config validate

# 2. Check detection with the VPN connected
vpnchecker diagnose
vpnchecker procs        # the Claude / Cursor / Rider processes that will be frozen

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
| `procs` | no | List the Claude / Cursor / Rider processes covered (STAT `T` = frozen) |
| `diagnose` | no | Interfaces, checks, GlobalProtect connection, protected servers, resolved allowlist domains, learned gateways |
| `reload` | owner | Reload the config in the running daemon (same as `SIGHUP`) |
| `allow <domain\|URL>` | owner | Add a domain (with subdomains) to `allow.domains` in the config, keeping comments, and reload the daemon |
| `update [--check]` | yes (no with `--check`) | Install the latest release now and restart the daemon; `--check` only reports whether one is available |
| `logs [-f] [-n N]` | no | Show `/var/log/vpnchecker.log` |
| `config init [--force]` / `validate` / `path` | no | Manage the config file |
| `run [--dry-run]` | yes (no with `--dry-run`) | Run in the foreground. `--dry-run` logs rules and what would be frozen instead of doing it |

Global options: `--config <path>` (env `VPNCHECKER_CONFIG`), `--socket <path>` (default `/var/run/vpnchecker.sock`), `-v`/`-vv`.

## Configuration

Path: `~/.config/vpnchecker/config.yaml`. Unknown fields are rejected. Full annotated example: [config.example.yaml](config.example.yaml).

```yaml
mode: full                      # full (default) | scoped

vpn:
  interface_pattern: '^(utun\d+|gpd\d+)$'
  subnets: [10.4.0.0/16]        # VPN address pool, required
  check_globalprotect: true

protect:                        # Claude / Cursor / Rider, always active
  freeze: false                 # full mode: also freeze the apps (always on in scoped)
  action: stop                  # stop (freeze) | kill
  dns_shield: true
  pf_block: true
  observe_connections: false
  extra_process_patterns: []    # add your own regexes
  wake_gap: 3s
  wake_hold: 5s
  resume_checks: 4

update:
  auto: true                    # look for newer releases
  confirm: true                 # ask before installing one
  interval: 24h
```

Everything under `protect` has a default covering Claude.app, Claude Code (`claude`), Cursor.app, `cursor-agent`, Rider.app (including `Rider.Backend` and `fsnotifier`), their extensions and every child process; run `vpnchecker procs` to see what matches on your machine.

**`vpn.subnets`:** the address pool the VPN assigns. Look at the `utunN` address with the VPN connected (`ifconfig`); GlobalProtect hands out a different address each time, so use the whole pool (e.g. `10.4.0.0/16`), not one address.

**What to put into `allow`:** for the VPN itself with GlobalProtect usually nothing. It matters in `full` mode: the VPN client must be able to reconnect (other VPN clients, and above all the identity provider of a SAML / SSO login, e.g. `vpnchecker allow jumpcloud.com`), and services that should keep working without the VPN go there too, with all their subdomains: `vpnchecker allow telegram.org`. A domain cannot be in `allow.domains` and `protect.domains` at the same time.

## Verification

```sh
vpnchecker status
vpnchecker procs
sudo pfctl -a com.apple/vpnchecker -sr     # rules are always loaded, with or without the VPN
ls /etc/resolver                           # allow.domains always (forwarder); while the VPN is down also anthropic.com, claude.ai, cursor.sh, ... (shield)
```

Disconnect GlobalProtect (in `scoped` mode, or with `protect.freeze: true`): Claude, Cursor and Rider freeze within a fraction of a second (`vpnchecker procs` shows STAT `T`), `vpnchecker status` shows `Blocked`. Reconnect: after a second or two they resume. Closing and opening the laptop lid does the same, with a pause of about `wake_hold`.

## Troubleshooting

- **Claude / Cursor / Rider stay frozen although the VPN is up** — `vpnchecker status` and `vpnchecker check` show which check fails (usually `vpn.subnets` does not contain the tunnel address, or GlobalProtect reports a state containing "disconnect"). Fix the config and `vpnchecker reload`, or `sudo vpnchecker stop` to release everything.
- **After a crash apps are still frozen** — `sudo vpnchecker stop`, or `sudo pkill -CONT -f 'Claude.app|Cursor.app|Rider.app'`.
- **A protected domain does not resolve although the VPN is up** — the shield files are removed when the VPN is verified; `sudo vpnchecker stop` removes them at once (`ls /etc/resolver` shows files starting with `# managed by vpnchecker`). vpnchecker never touches resolver files it did not write.
- **`full` mode: the VPN does not reconnect while blocked** — the client needs a host that is not allowlisted. Gateways under `allow.gateway_suffixes` and the captive-portal probe (`allow.probe_hosts`) are covered automatically. What usually remains is the **identity provider of a SAML / SSO login**: its page opens in the browser and must load without the VPN, e.g. `vpnchecker allow jumpcloud.com` (`okta.com`, `login.microsoftonline.com`, ...). The login works without it only while GlobalProtect's saved auth cookie is valid, so add it before you need it. Already locked out: `sudo vpnchecker stop`, connect, add the host, `sudo vpnchecker start`. `vpnchecker diagnose` lists the zones in effect. Consider `scoped` mode, which never touches the VPN client's traffic.
- **Captive portals** (hotels, airports) — in `scoped` mode the login page just works (only Claude / Cursor / Rider are held back). In `full` mode: `sudo vpnchecker stop`, log in, `sudo vpnchecker start`.
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
- **Trust:** the daemon is root and reads a user-owned config and the user-writable GlobalProtect event log. The config holds only patterns, host names, subnets and timings (host names are validated strictly because they become file names), but a user who can edit it can make the daemon freeze arbitrary processes. Log-derived hosts are filtered by `gateway_suffixes`. Auto-update trusts this repository's GitHub releases exactly as the install one-liner does: the checksum guards against a damaged download, not against a compromised release, and whoever can publish a release gets root on every machine that accepts it. Asking first, the default, keeps a person in that loop; `update.confirm: false` takes them out. Turn it off with `update.auto: false`; pin a version with `VPNCHECKER_VERSION=vX.Y.Z` on the installer.
- First start with the VPN down and an empty cache has no kernel block yet (nothing learned); the freeze and DNS shield still apply.

## Development

```sh
cargo test
cargo clippy --all-targets
vpnchecker --socket ./vc.sock run --dry-run -v    # needs no root, shows what would be frozen
```

Tests cover the state machine (`guard`), process selection and real SIGSTOP / SIGCONT on a child process, the DNS responder over real UDP, pf rule rendering, GlobalProtect plist parsing and config validation.

Release: automatic. Every merge to `master` that touches `src/`, `Cargo.*` or `install.sh` runs the `release` workflow: it bumps the patch version (or takes a `version` raised in the PR; *Run workflow* offers minor / major), commits and tags it, builds the universal binary, publishes it with `install.sh` to GitHub Releases and the crate to crates.io (secret `CARGO_REGISTRY_TOKEN`). Machines with `update.auto` offer it to their user within `update.interval` (or install it at once with `update.confirm: false`), so a release must keep accepting existing configs: one that rejects a config is skipped on that machine.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at your option.
