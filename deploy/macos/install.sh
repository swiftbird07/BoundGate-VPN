#!/bin/sh
# Install or remove the node as a LaunchDaemon. Run with sudo.
#   sudo deploy/macos/install.sh install path/to/node.yaml
#   sudo deploy/macos/install.sh uninstall        # keeps /var/db/boundgate (the device key)
#   sudo PREFIX=/opt/boundgate deploy/macos/install.sh install node.yaml   # when /usr/local is not root's
#
# The daemon runs as root. Whoever can replace its program, its helper, its
# configuration or the directories they are in owns the Mac: every one of
# them and every directory above it must belong to root and be writable by
# nobody else. On an Intel Mac with Homebrew, /usr/local/bin and
# /usr/local/etc belong to the user who installed Homebrew: the script then
# refuses and says so; PREFIX=/opt/boundgate installs into a tree of its own.
set -eu
REPO=$(cd "$(dirname "$0")/../.." && pwd)
ARCH=$(uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/')
BIN=$REPO/bin/darwin_$ARCH
PLIST=/Library/LaunchDaemons/com.boundgate.node.plist
PREFIX=${PREFIX:-/usr/local}
case "$PREFIX" in /*) ;; *) echo "PREFIX must be an absolute path" >&2; exit 2 ;; esac
case "$PREFIX" in *[!A-Za-z0-9/._-]*) echo "PREFIX: letters, digits and / . _ - only" >&2; exit 2 ;; esac
BINDIR=$PREFIX/bin
ETC=$PREFIX/etc/boundgate
[ "$(id -u)" = 0 ] || { echo "run with sudo" >&2; exit 1; }
die() { echo "install: $*" >&2; exit 1; }

# root_only PATH: PATH and every directory above it belong to root, are no
# links, and neither group nor others may write to them. Checked on the
# physical path (/var is a link to /private/var); PATH itself is no link.
root_only() {
  [ ! -L "$1" ] || die "$1 is a symbolic link: refusing (the daemon runs as root)"
  if [ -d "$1" ]; then p=$(cd -P "$1" && pwd); else p=$(cd -P "$(dirname "$1")" && pwd)/$(basename "$1"); fi
  while :; do
    [ -e "$p" ] || die "$p does not exist"
    [ ! -L "$p" ] || die "$p is a symbolic link: refusing (the daemon runs as root)"
    owner=$(stat -f %u "$p"); mode=$(stat -f %Lp "$p")
    [ "$owner" = 0 ] || die "$p belongs to $(stat -f %Su "$p"), not root: whoever owns it can replace what root runs. Use PREFIX=/opt/boundgate, or give it to root"
    [ $((0$mode & 022)) = 0 ] || die "$p is writable by its group or others ($mode): refusing. Use PREFIX=/opt/boundgate, or chmod go-w it"
    [ "$p" != / ] || return 0
    p=$(dirname "$p")
  done
}
# ours DIR MODE: a directory only BoundGate uses; created or corrected to root:wheel
ours() { mkdir -p "$1" && chown root:wheel "$1" && chmod "$2" "$1"; }

case "${1:-}" in
  install)
    CFG=${2:?usage: install.sh install node.yaml}
    for f in boundgate-node boundgatectl; do [ -f "$BIN/$f" ] || die "$BIN/$f is missing (make build-darwin)"; done
    # shared directories are created if missing (then root's), never taken over
    [ -d "$BINDIR" ] || (umask 022; mkdir -p "$BINDIR")
    [ -d "$PREFIX/etc" ] || (umask 022; mkdir -p "$PREFIX/etc")
    root_only "$BINDIR"; root_only "$PREFIX/etc"; root_only /Library/LaunchDaemons
    # from here on the physical paths: they go into the LaunchDaemon, and every part of them was checked
    BINDIR=$(cd -P "$BINDIR" && pwd); ETC=$(cd -P "$PREFIX/etc" && pwd)/boundgate
    ours "$ETC" 755; ours "$ETC/profiles" 755; ours /var/log/boundgate 755; ours /var/db/boundgate 700
    for d in "$ETC/profiles" /var/log/boundgate /var/db/boundgate; do root_only "$d"; done
    for f in boundgate-node boundgatectl boundgate-sekey; do
      [ -f "$BIN/$f" ] || continue # boundgate-sekey: the Secure Enclave bridge (make mac-sekey); the daemon looks for it next to itself
      install -o root -g wheel -m 755 "$BIN/$f" "$BINDIR/.$f.new" && mv -f "$BINDIR/.$f.new" "$BINDIR/$f"
      root_only "$BINDIR/$f"
    done
    install -o root -g wheel -m 600 "$CFG" "$ETC/node.yaml"; root_only "$ETC/node.yaml"
    sed -e "s|/usr/local/bin/|$BINDIR/|g" -e "s|/usr/local/etc/boundgate/|$ETC/|g" "$REPO/deploy/macos/com.boundgate.node.plist" > "$PLIST.new"
    chown root:wheel "$PLIST.new"; chmod 644 "$PLIST.new"; mv -f "$PLIST.new" "$PLIST"; root_only "$PLIST"
    launchctl bootout system "$PLIST" 2>/dev/null || true
    launchctl bootstrap system "$PLIST"
    echo "installed into $BINDIR and $ETC; boundgatectl talks to /var/run/boundgate/node.sock (sudo, or add your user to the socket's group)" ;;
  uninstall)
    # where it was installed: the program the LaunchDaemon names
    prog=$(/usr/libexec/PlistBuddy -c 'Print :ProgramArguments:0' "$PLIST" 2>/dev/null || echo "$BINDIR/boundgate-node")
    cfg=$(/usr/libexec/PlistBuddy -c 'Print :ProgramArguments:2' "$PLIST" 2>/dev/null || echo "$ETC/node.yaml")
    bindir=$(dirname "$prog"); etc=$(dirname "$cfg")
    case "$etc" in */boundgate) ;; *) die "the LaunchDaemon names $cfg; not removing $etc" ;; esac
    "$bindir/boundgatectl" down 2>/dev/null || true
    launchctl bootout system "$PLIST" 2>/dev/null || true
    rm -f "$PLIST" "$bindir/boundgate-node" "$bindir/boundgatectl" "$bindir/boundgate-sekey"
    rm -rf "$etc" /var/run/boundgate
    echo "removed; the device identity stays in /var/db/boundgate (delete it to forget this node)" ;;
  *) sed -n '2,5p' "$0"; exit 2 ;;
esac
