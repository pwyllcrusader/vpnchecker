#!/bin/sh
# vpnchecker installer / updater for macOS:
#   curl -fsSL https://github.com/pwyllcrusader/vpnchecker/releases/latest/download/install.sh | sh
#   curl -fsSL https://github.com/pwyllcrusader/vpnchecker/releases/latest/download/install.sh | sh -s -- --mode scoped
# Options: --mode scoped|full (or VPNCHECKER_MODE) sets `mode` in the config, also when it already exists.
# A specific release: VPNCHECKER_VERSION=v0.1.1. Install without a detected VPN: VPNCHECKER_FORCE=1.
set -eu

REPO="pwyllcrusader/vpnchecker"
ASSET="vpnchecker-macos-universal.tar.gz"
BIN="/Library/PrivilegedHelperTools/vpnchecker"
PLIST="/Library/LaunchDaemons/com.vpnchecker.daemon.plist"
LINK="/usr/local/bin/vpnchecker"

say() { printf '\033[1m==> %s\033[0m\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

usage() {
    cat <<EOF
usage: install.sh [--mode scoped|full]
  --mode full     block all traffic outside the VPN (default of a new config)
  --mode scoped   restrict only Claude, Cursor and Rider; the rest of the Mac keeps working
Through the one-liner: curl -fsSL .../install.sh | sh -s -- --mode scoped
Environment: VPNCHECKER_MODE (same as --mode), VPNCHECKER_VERSION=vX.Y.Z, VPNCHECKER_FORCE=1
EOF
}

# Current value of the top-level `mode:` key, empty if absent.
config_mode() { sed -n 's/^mode:[[:space:]]*\([A-Za-z]*\).*/\1/p' "$1" | head -n 1; }

# Sets `mode:` in the config in place, keeping comments and layout.
set_mode() { # $1 = config, $2 = mode
    if grep -q '^mode:' "$1"; then
        if [ "$(config_mode "$1")" = "$2" ]; then
            say "mode is already $2 in $1"
            return
        fi
        sed -i '' "s/^mode:[[:space:]]*[A-Za-z]*/mode: $2/" "$1"
    else
        { printf 'mode: %s\n' "$2"; cat "$1"; } >"$1.new" && mv "$1.new" "$1"
    fi
    say "mode set to $2 in $1"
}

# Wrapped in a function so a truncated download cannot run half a script.
main() {
    mode=${VPNCHECKER_MODE:-}
    while [ $# -gt 0 ]; do
        case $1 in
            --mode) [ $# -ge 2 ] || die "--mode needs a value (scoped or full)"; mode=$2; shift 2 ;;
            --mode=*) mode=${1#--mode=}; shift ;;
            -h|--help) usage; exit 0 ;;
            *) die "unknown option $1 (try --help)" ;;
        esac
    done
    case $mode in
        ''|scoped|full) ;;
        *) die "mode must be scoped or full, not '$mode'" ;;
    esac

    [ "$(uname -s)" = Darwin ] || die "vpnchecker supports macOS only"
    [ "$(id -u)" -ne 0 ] || die "run this as your user, not root: it calls sudo itself"

    if [ -n "${VPNCHECKER_VERSION:-}" ]; then
        base="https://github.com/$REPO/releases/download/$VPNCHECKER_VERSION"
    else
        base="https://github.com/$REPO/releases/latest/download"
    fi

    tmp=$(mktemp -d)
    trap 'rm -rf "$tmp"' EXIT

    say "Downloading vpnchecker"
    curl --proto '=https' --tlsv1.2 -fsSL "$base/$ASSET" -o "$tmp/$ASSET"
    curl --proto '=https' --tlsv1.2 -fsSL "$base/$ASSET.sha256" -o "$tmp/$ASSET.sha256"
    (cd "$tmp" && shasum -a 256 -c "$ASSET.sha256" >/dev/null) || die "checksum mismatch, aborting"
    tar -xzf "$tmp/$ASSET" -C "$tmp"
    new="$tmp/vpnchecker"
    "$new" --version

    config=$("$new" config path)
    if [ ! -f "$config" ]; then
        say "Creating $config"
        "$new" config init
    fi
    if [ -n "$mode" ]; then
        set_mode "$config" "$mode"
    fi
    "$new" config validate

    # A first install with an undetected VPN would cut the internet right away.
    if [ ! -f "$PLIST" ] && [ -z "${VPNCHECKER_FORCE:-}" ] && ! "$new" check; then
        cat >&2 <<EOF

The VPN is not detected, nothing was installed.
Connect the VPN and run the same command again. If it is connected, set vpn.subnets in
  $config
to the VPN address pool (the utun address from: ifconfig | grep 'inet ') and run again.
EOF
        exit 1
    fi

    say "Installing the daemon (sudo asks for your Mac password)"
    sudo "$new" install

    if [ -e "$LINK" ] && [ ! -L "$LINK" ]; then
        say "$LINK exists and is not a symlink, leaving it alone; the CLI is $BIN"
    else
        sudo mkdir -p "$(dirname "$LINK")"
        sudo ln -sf "$BIN" "$LINK"
    fi

    sleep 1
    "$BIN" status || true

    if [ "$(config_mode "$config")" = scoped ]; then
        printf '\nDone (mode: scoped). Without the VPN only Claude, Cursor and Rider are held back.\n'
    else
        printf '\nDone (mode: full). Without the VPN only allowlisted hosts are reachable.\n'
    fi
    cat <<EOF
  vpnchecker allow telegram.org    # allow a domain and its subdomains without the VPN
  vpnchecker status                # state
  vpnchecker logs -f               # daemon log
  sudo vpnchecker update           # update now (or run the same install command again)
  sudo vpnchecker uninstall        # remove everything
New releases install by themselves while the VPN is up; turn that off with update.auto: false in the config.
EOF
}

main "$@"
