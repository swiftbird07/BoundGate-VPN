#!/bin/sh
# Install or remove the node as a LaunchDaemon. Run with sudo.
#   sudo deploy/macos/install.sh install path/to/node.yaml
#   sudo deploy/macos/install.sh uninstall        # keeps /var/db/boundgate (the device key)
set -eu
REPO=$(cd "$(dirname "$0")/../.." && pwd)
ARCH=$(uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/')
BIN=$REPO/bin/darwin_$ARCH
PLIST=/Library/LaunchDaemons/com.boundgate.node.plist
[ "$(id -u)" = 0 ] || { echo "run with sudo" >&2; exit 1; }
case "${1:-}" in
  install)
    CFG=${2:?usage: install.sh install node.yaml}
    install -d -m 755 /usr/local/bin /usr/local/etc/boundgate /usr/local/etc/boundgate/profiles /var/log/boundgate
    install -d -m 700 /var/db/boundgate
    install -m 755 "$BIN/boundgate-node" "$BIN/boundgatectl" /usr/local/bin/
    install -m 600 "$CFG" /usr/local/etc/boundgate/node.yaml
    install -m 644 "$REPO/deploy/macos/com.boundgate.node.plist" "$PLIST"
    launchctl bootout system "$PLIST" 2>/dev/null || true
    launchctl bootstrap system "$PLIST"
    echo "installed; boundgatectl talks to /var/run/boundgate/node.sock (sudo, or add your user to the socket's group)" ;;
  uninstall)
    /usr/local/bin/boundgatectl down 2>/dev/null || true
    launchctl bootout system "$PLIST" 2>/dev/null || true
    rm -f "$PLIST" /usr/local/bin/boundgate-node /usr/local/bin/boundgatectl
    rm -rf /usr/local/etc/boundgate /var/run/boundgate
    echo "removed; the device identity stays in /var/db/boundgate (delete it to forget this node)" ;;
  *) sed -n '2,5p' "$0"; exit 2 ;;
esac
