#!/bin/sh
# vpnchecker installer / updater for macOS:
#   curl -fsSL https://github.com/pwyllcrusader/vpnchecker/releases/latest/download/install.sh | sh
# A specific release: VPNCHECKER_VERSION=v0.1.1. Install without a detected VPN: VPNCHECKER_FORCE=1.
set -eu

REPO="pwyllcrusader/vpnchecker"
ASSET="vpnchecker-macos-universal.tar.gz"
BIN="/Library/PrivilegedHelperTools/vpnchecker"
PLIST="/Library/LaunchDaemons/com.vpnchecker.daemon.plist"
LINK="/usr/local/bin/vpnchecker"

say() { printf '\033[1m==> %s\033[0m\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

# Wrapped in a function so a truncated download cannot run half a script.
main() {
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

    cat <<EOF

Done. Without the VPN only allowlisted hosts are reachable.
  vpnchecker allow telegram.org    # allow a domain and its subdomains without the VPN
  vpnchecker status                # state
  vpnchecker logs -f               # daemon log
  sudo vpnchecker uninstall        # remove everything
Update: run the same install command again.
EOF
}

main "$@"
