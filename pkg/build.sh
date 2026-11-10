#!/bin/sh
# Builds the macOS installer package (opened in Installer by a double click):
#   pkg/build.sh <vpnchecker binary> <output.pkg>
# The version comes from the binary. PKG_SIGN_IDENTITY="Developer ID Installer: Name (TEAMID)" signs the package;
# without it the package is unsigned and Gatekeeper asks the user to confirm opening it.
set -eu

[ $# -eq 2 ] || { echo "usage: pkg/build.sh <vpnchecker binary> <output.pkg>" >&2; exit 2; }
bin=$1
out=$2
here=$(cd "$(dirname "$0")" && pwd)

version=$("$bin" --version | sed -n 's/^vpnchecker //p')
[ -n "$version" ] || { echo "error: $bin did not report a version" >&2; exit 1; }

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir "$work/scripts" "$work/resources"

# No payload: the binary rides in the scripts archive and installs itself (see scripts/postinstall).
install -m 755 "$here/scripts/postinstall" "$bin" "$work/scripts/"
[ "$(basename "$bin")" = vpnchecker ] || mv "$work/scripts/$(basename "$bin")" "$work/scripts/vpnchecker"
for page in "$here"/resources/*.html; do
    sed "s/@VERSION@/$version/g" "$page" >"$work/resources/$(basename "$page")"
done
sed "s/@VERSION@/$version/g" "$here/distribution.xml" >"$work/distribution.xml"

pkgbuild --quiet --nopayload --scripts "$work/scripts" \
    --identifier com.vpnchecker.pkg --version "$version" "$work/built.pkg"
# pkgbuild has no option for the script timeout and writes 600 seconds; setup waits for the user (connecting the
# VPN can mean a browser login), so the component is unpacked, given an hour and packed again. The ._ files that
# pkgbuild packs for extended attributes of the build machine are dropped on the way.
pkgutil --expand "$work/built.pkg" "$work/component"
find "$work/component" -name '._*' -delete
sed -i '' 's/\(<postinstall [^>]*timeout="\)[0-9]*"/\13600"/' "$work/component/PackageInfo"
grep -q 'timeout="3600"' "$work/component/PackageInfo" || { echo "error: could not set the script timeout" >&2; exit 1; }
COPYFILE_DISABLE=1 pkgutil --flatten "$work/component" "$work/vpnchecker-component.pkg"

if [ -n "${PKG_SIGN_IDENTITY:-}" ]; then
    productbuild --quiet --distribution "$work/distribution.xml" --resources "$work/resources" \
        --package-path "$work" --sign "$PKG_SIGN_IDENTITY" "$out"
else
    productbuild --quiet --distribution "$work/distribution.xml" --resources "$work/resources" \
        --package-path "$work" "$out"
fi
echo "built $out (vpnchecker $version, $([ -n "${PKG_SIGN_IDENTITY:-}" ] && echo signed || echo unsigned))"
