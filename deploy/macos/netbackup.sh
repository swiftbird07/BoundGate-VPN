#!/bin/sh
# Snapshot, compare and repair the Mac's network state around BoundGate tests.
#
#   deploy/macos/netbackup.sh backup            # read-only; writes deploy/macos/backups/<timestamp>/
#   deploy/macos/netbackup.sh diff [DIR]        # what differs now from the (latest) backup
#   deploy/macos/netbackup.sh restore [DIR]     # stop the node, show the repair commands
#   deploy/macos/netbackup.sh restore -y [DIR]  # ... and run them (sudo)
#
# What a BoundGate node can change on macOS: one utun device with an overlay
# address, routes through it, and host ("bypass") routes for hubs and the
# control plane. It never touches DNS, proxies, pf, sysctls or the saved
# network services. All of that is runtime state: a reboot (or Wi-Fi off/on
# for the default route) clears whatever is left. The backup still records
# DNS, proxies, services and the system configuration files, so that anything
# unexpected is visible in `diff`.
set -eu
REPO=$(cd "$(dirname "$0")/../.." && pwd)
ROOT=$REPO/deploy/macos/backups
cmd=${1:-}; [ $# -gt 0 ] && shift
YES=0; [ "${1:-}" = "-y" ] && { YES=1; shift; }
latest() { ls -1d "$ROOT"/*/ 2>/dev/null | sort | tail -1 | sed 's#/$##'; }

# routes as "family dest gateway flags netif", destinations expanded
# (10.60/24 -> 10.60.0.0/24). Cloned (W) and link-layer (L) entries are the
# kernel's per-destination cache (ARP, recently used hosts); they come and go
# by themselves and are left out. netstat-rn.txt keeps the raw table.
routes() {
  for fam in inet inet6; do
    netstat -rn -f $fam | awk -v fam=$fam '
      $1 == "Destination" { on = 1; next } !on || NF < 4 { next }
      $3 ~ /[WL]/ { next }
      { d = $1
        if (fam == "inet" && d != "default") {
          split(d, p, "/"); n = split(p[1], o, ".")
          if (n < 4 && p[1] ~ /^[0-9.]+$/) { for (i = n + 1; i <= 4; i++) p[1] = p[1] ".0"; d = p[1] (p[2] != "" ? "/" p[2] : (n == 1 ? "/8" : n == 2 ? "/16" : "/24")) }
        }
        print fam, d, $2, $3, $4 }'
  done | sort -u
}

snapshot() {  # snapshot DIR: everything read-only
  d=$1; mkdir -p "$d"
  date > "$d/taken_at"; sw_vers > "$d/sw_vers" 2>&1 || true
  routes > "$d/routes.txt"
  netstat -rn > "$d/netstat-rn.txt" 2>&1
  ifconfig -a > "$d/ifconfig.txt" 2>&1
  ifconfig -l > "$d/interfaces.txt" 2>&1
  route -n get default > "$d/default-route.txt" 2>&1 || true
  route -n get -inet6 default > "$d/default-route6.txt" 2>&1 || true
  scutil --dns > "$d/scutil-dns.txt" 2>&1 || true
  scutil --proxy > "$d/scutil-proxy.txt" 2>&1 || true
  scutil --nwi > "$d/scutil-nwi.txt" 2>&1 || true
  networksetup -listnetworkserviceorder > "$d/service-order.txt" 2>&1 || true
  networksetup -listallhardwareports > "$d/hardware-ports.txt" 2>&1 || true
  networksetup -listallnetworkservices 2>/dev/null | sed 1d | sed 's/^\*//' | while IFS= read -r svc; do
    f="$d/service-$(printf '%s' "$svc" | tr -c 'A-Za-z0-9' '_').txt"
    { echo "== $svc"; networksetup -getinfo "$svc"; echo "-- dns"; networksetup -getdnsservers "$svc"; echo "-- search"; networksetup -getsearchdomains "$svc"
      echo "-- web proxy"; networksetup -getwebproxy "$svc"; echo "-- secure web proxy"; networksetup -getsecurewebproxy "$svc"; echo "-- auto proxy"; networksetup -getautoproxyurl "$svc"; } > "$f" 2>&1 || true
  done
  sysctl net.inet.ip.forwarding net.inet6.ip6.forwarding net.inet.ip.redirect > "$d/sysctl.txt" 2>&1 || true
  arp -an > "$d/arp.txt" 2>&1 || true
  ndp -an > "$d/ndp.txt" 2>&1 || true
  cp /etc/hosts "$d/etc-hosts" 2>/dev/null || true
  cp /etc/resolv.conf "$d/etc-resolv.conf" 2>/dev/null || true
  ls -la /etc/resolver > "$d/etc-resolver.txt" 2>&1 || true
  for f in preferences.plist NetworkInterfaces.plist; do cp "/Library/Preferences/SystemConfiguration/$f" "$d/$f" 2>/dev/null || echo "not readable" > "$d/$f.unreadable"; done
  (sudo -n pfctl -sr 2>/dev/null || echo "pf rules need root (not recorded; BoundGate does not use pf on macOS)") > "$d/pf-rules.txt"
  pgrep -fl 'boundgate-(node|udpbridge)' > "$d/boundgate-processes.txt" 2>&1 || true
}

case "$cmd" in
  routes) routes ;;
  backup)
    dir=$ROOT/$(date +%Y%m%d-%H%M%S)
    snapshot "$dir"
    echo "backup: $dir"
    echo "  default route: $(awk '/gateway:/{g=$2} /interface:/{i=$2} END{print g " via " i}' "$dir/default-route.txt")"
    echo "  routes: $(wc -l < "$dir/routes.txt" | tr -d ' ')   interfaces: $(wc -w < "$dir/interfaces.txt" | tr -d ' ')   utun: $(tr ' ' '\n' < "$dir/interfaces.txt" | grep -c '^utun' || true)"
    echo "  dns resolvers: $(grep -c 'nameserver\[' "$dir/scutil-dns.txt" || true)"
    if [ -s "$dir/boundgate-processes.txt" ]; then echo "  NOTE: a BoundGate process is running; this is not a clean baseline"; fi ;;
  diff)
    base=${1:-$(latest)}; [ -n "$base" ] && [ -d "$base" ] || { echo "no backup found; run: $0 backup" >&2; exit 1; }
    tmp=$(mktemp -d); snapshot "$tmp"
    echo "comparing now with $base ($(cat "$base/taken_at"))"
    rc=0
    for f in routes.txt interfaces.txt scutil-dns.txt scutil-proxy.txt sysctl.txt etc-hosts service-order.txt preferences.plist; do
      if ! diff -q "$base/$f" "$tmp/$f" >/dev/null 2>&1; then rc=1; echo "--- $f differs:"; diff "$base/$f" "$tmp/$f" | sed 's/^/    /' | head -40; fi
    done
    [ $rc = 0 ] && echo "identical: routes, interfaces, DNS, proxies, sysctls, /etc/hosts, service order, saved preferences"
    rm -rf "$tmp"; exit $rc ;;
  restore)
    base=${1:-$(latest)}; [ -n "$base" ] && [ -d "$base" ] || { echo "no backup found" >&2; exit 1; }
    echo "restoring towards $base ($(cat "$base/taken_at"))"
    run() { echo "  $*"; [ $YES = 1 ] && { "$@" || true; }; }
    echo "1. stop BoundGate (the utun device and every route through it go away with the process)"
    "$REPO/deploy/macos/dev.sh" ctl down >/dev/null 2>&1 || true
    run sudo pkill -f 'darwin_.*/boundgate-node'
    run pkill -f 'darwin_.*/boundgate-udpbridge'
    [ $YES = 1 ] && sleep 2
    now=$(mktemp); routes > "$now"
    echo "2. routes that exist now but not in the backup (static host routes and routes on new utun devices are removed; others only shown)"
    comm -13 "$base/routes.txt" "$now" | while read -r fam dest gw flags netif; do
      famflag=-inet; [ "$fam" = inet6 ] && famflag=-inet6
      newutun=0; case "$netif" in utun*) grep -qw "$netif" "$base/interfaces.txt" || newutun=1 ;; esac
      case "$flags" in
        *H*S*|*S*H*) run sudo route -n delete $famflag -host "$dest" ;;
        *) if [ $newutun = 1 ]; then run sudo route -n delete $famflag -net "$dest" -interface "$netif"; else echo "  (left alone: $fam $dest via $gw on $netif [$flags])"; fi ;;
      esac
    done
    echo "3. routes from the backup that are missing now (only the default route is re-added; the rest is shown)"
    comm -23 "$base/routes.txt" "$now" | while read -r fam dest gw flags netif; do
      if [ "$dest" = default ] && [ "$fam" = inet ] && ! grep -q '^inet default ' "$now"; then run sudo route -n add default "$gw"
      else echo "  (missing: $fam $dest via $gw on $netif [$flags]; dynamic routes come back by themselves)"; fi
    done
    rm -f "$now" "$REPO/deploy/macos/state/netstate.json" 2>/dev/null || true
    echo "4. still wrong? Wi-Fi off/on renews the default route and DNS:"
    echo "     networksetup -setairportpower en0 off && networksetup -setairportpower en0 on"
    echo "   and a reboot clears every runtime route. Saved settings were never modified; compare with: $0 diff $base"
    [ $YES = 1 ] || echo "(dry run: nothing was changed except 'boundgatectl down'; add -y to execute)" ;;
  *) sed -n '2,8p' "$0"; exit 2 ;;
esac
