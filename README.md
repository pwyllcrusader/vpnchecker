# vpnchecker

[Русская версия](README.ru.md)

A VPN kill switch for macOS. Outbound traffic is allowed **only through the VPN interface**; without the VPN nothing reaches the internet except the VPN client itself (portal / gateways) and the local network. Built for GlobalProtect, works with any VPN that creates a `utunN` interface.

## How it works

The daemon keeps a [pf](https://man.openbsd.org/pf.conf) ruleset loaded at all times in the anchor `com.apple/vpnchecker` (the stock `/etc/pf.conf` already evaluates `com.apple/*`, so system config is not modified):

```
pass out quick on lo0 all                                # localhost
pass out quick on utun4 all keep state (if-bound)        # the tunnel
pass out quick proto { tcp udp } to any port 53          # DNS
pass out quick proto udp to any port { 67 68 123 546 547 }  # DHCP, NTP
pass out quick inet6 proto icmp6 all                     # IPv6 neighbor discovery
pass out quick to <vpnchecker_allow>                     # VPN portal/gateways, LAN
block return out quick all                               # everything else
```

macOS picks the egress interface before pf sees the packet. While the VPN is up, the default route goes through `utun4` and traffic passes. When the VPN drops, the route switches to `en0` and **the kernel blocks the very next packet** — there is no reaction window and no dependency on the daemon being fast.

The daemon:

- **Tracks the VPN interface.** The VPN is up when an interface matching `interface_pattern` has an address from `vpn.subnets` **and** the default route goes through it (GlobalProtect keeps `utunN` with a pool address after disconnect, so the interface alone is not enough). Checks run immediately on every kernel routing / address / interface change (`PF_ROUTE` socket) and by `check.interval` as a fallback. If the interface changes (`utun4` → `utun5`), the rule is rewritten.
- **Keeps the allowlist current** so the VPN client can reconnect while everything is blocked:
  - `allow.domains` are re-resolved every `resolve_interval` and right after the VPN drops (split-horizon DNS answers differently on and off the VPN);
  - `allow.globalprotect` discovers the portal (`Portal` / `LastUrl` in the GlobalProtect settings plists) and gateways (host names in `pan_gp_event.log`). While the VPN is down the log is followed on every check, so a gateway the client has just started trying is allowed within seconds;
  - `allow.learn_gateways` adds VPN gateways seen as host routes outside the tunnel while the VPN is up;
  - every seen address is kept for `resolve_retain` and persisted in `/var/db/vpnchecker/cache.json`.
- **Drops tunnel connections** (pf states from `vpn.subnets`) when the VPN goes down; tunnel rules use `if-bound` states so no connection can fall back to `en0`.
- **Survives its own exit.** On `SIGTERM` / `SIGINT` (launchd stop, `kill`) it leaves rules that pass only traffic *sourced from `vpn.subnets`* — i.e. traffic going through the tunnel — so the internet comes back by itself when the VPN reconnects, and stays blocked otherwise. On a crash or `SIGKILL` the last loaded rules simply stay in pf. launchd restarts the daemon in both cases.
- **Notifies** (macOS notification) when the VPN goes up / down.

## Requirements

- macOS
- Rust (to build)
- `sudo` for installation (pf requires root)

## Installation

```sh
cargo install --path .

# 1. Create the config and set vpn.subnets and allow.* (see Configuration)
vpnchecker config init
$EDITOR ~/.config/vpnchecker/config.yaml
vpnchecker config validate

# 2. Check detection (VPN connected)
vpnchecker diagnose

# 3. Install as a launchd daemon
sudo "$(which vpnchecker)" install
vpnchecker status
```

`install` copies the **running** binary to `/Library/PrivilegedHelperTools/vpnchecker` (owned by `root:wheel`, so a regular user cannot swap it), writes `/Library/LaunchDaemons/com.vpnchecker.daemon.plist` and starts the daemon. It starts on boot and is restarted if it exits. Use the full path with `sudo` — sudo has its own `PATH`. Re-run `install` after every upgrade.

## Commands

| Command | Root | Description |
|---|---|---|
| `install` / `uninstall` | yes | Install / remove the launchd daemon (`uninstall` also removes pf rules) |
| `start` / `restart` | yes | Start / restart the installed daemon |
| `stop [--keep-block]` | yes | Stop the daemon and remove its pf rules (`--keep-block` keeps the exit rules) |
| `flush` | yes | Remove vpnchecker pf rules immediately |
| `status [--json]` | no | VPN state, interface, allowlist size, checks |
| `check [-q]` | no | Check the VPN once. Exit code: `0` up, `1` down, `2` error |
| `diagnose` | no | Interfaces, checks, resolved allowlist domains, discovered GlobalProtect hosts, learned VPN gateways |
| `reload` | owner | Reload the config in the running daemon (same as `SIGHUP`) |
| `logs [-f] [-n N]` | no | Show `/var/log/vpnchecker.log` |
| `config init [--force]` / `validate` / `path` | no | Manage the config file |
| `run [--dry-run]` | yes (no with `--dry-run`) | Run in the foreground. `--dry-run` logs rules instead of applying them |

Global options: `--config <path>` (env `VPNCHECKER_CONFIG`), `--socket <path>` (default `/var/run/vpnchecker.sock`), `-v`/`-vv`.

## Configuration

Path: `~/.config/vpnchecker/config.yaml`. Unknown fields are rejected. Example: [config.example.yaml](config.example.yaml).

```yaml
vpn:
  interface_pattern: '^(utun\d+|gpd\d+)$'   # GlobalProtect: utunN (older: gpd0)
  subnets: [10.4.0.0/16, 10.5.0.0/16]       # VPN address pool, required

allow:
  lan: true                  # RFC1918, link-local, multicast, IPv6 ULA
  learn_gateways: true       # auto-allow VPN gateways seen in the routing table
  globalprotect: true        # auto-allow portal/gateways from GlobalProtect settings and log
  domains:                   # extra VPN portal / gateway hosts
    - vpn.example.corp
    - us-east-g-example.gw.gpcloudservice.com
  cidrs: [203.0.113.5/32]

check:
  interval: 2s               # fallback polling
  timeout: 1500ms
  resolve_interval: 60s
  resolve_retain: 24h

notify: true
```

**What to put into `allow`:** with GlobalProtect usually nothing — `globalprotect` and `learn_gateways` find the portal and gateways (check with `vpnchecker diagnose`). Add hosts manually only for what they cannot see: other VPN clients, or the identity provider if SAML login opens its page while the tunnel is down.

**`vpn.subnets`:** the address pool the VPN assigns. Look at the `utunN` address with the VPN connected (`ifconfig`); GlobalProtect also lists previously assigned addresses in `defaults read /Library/Preferences/com.paloaltonetworks.GlobalProtect.settings` (`PreferredIP_*`).

The config is read by a root process but cannot execute anything: it contains only interface patterns, hosts, subnets and timings. The GlobalProtect log is writable by the user, so `globalprotect: true` trusts the user exactly as much as the config file does.

## Verification

```sh
vpnchecker status
sudo pfctl -a com.apple/vpnchecker -sr     # rules are always loaded, with or without the VPN
```

Disconnect the VPN: `curl -m5 https://example.com` must fail immediately, `vpnchecker status` shows `Down`. Reconnect: the VPN must come up and traffic must flow again.

## Troubleshooting

- **The VPN does not reconnect while blocked** — the client needs an address that is not allowlisted (new gateway, IdP for SAML). Run `sudo vpnchecker stop` (removes the rules), connect, run `vpnchecker diagnose` and the GlobalProtect log to find the host, add it to `allow`, `sudo vpnchecker start`.
- **Captive portals** (hotels, airports) — the login page is blocked without the VPN: quit apps that must not go out directly, `sudo vpnchecker stop`, log in, `sudo vpnchecker start`.
- **Daemon does not start** — `vpnchecker logs`. An `unknown field` error means the installed binary is older than the config: reinstall with `sudo "$(which vpnchecker)" install`.
- **Uninstall** — `sudo vpnchecker uninstall` removes the daemon, plist, binary and pf rules and releases the pf token.

## Claude Code hook (optional)

pf already blocks the traffic, but a hook gives a clear message instead of a network error. In `~/.claude/settings.json`:

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

- **Full tunnel only:** traffic that the VPN routes outside the tunnel (split-tunnel exclusions) is blocked.
- **No protection while stopped:** `stop`, `flush` and `uninstall` remove the rules, and after a reboot nothing is filtered until launchd starts the daemon. Quit apps that must not go out directly before stopping it.
- **Not per-process:** the rules apply to the whole machine. Per-process filtering requires a NetworkExtension.
- **DNS** (port 53) is allowed to any server, so name lookups go to the local resolver while the VPN is down.
- **IPv6:** blocked unless it goes through the tunnel or to the allowlist.

## Development

```sh
cargo test
cargo clippy --all-targets
vpnchecker --socket /tmp/vpnchecker.sock run --dry-run -v
```
