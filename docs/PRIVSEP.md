# Privilege separation

`boundgate-node` parses bytes that others chose: every packet from a tunnel,
a path or the host stack (IP, TCP, UDP, ICMP, DNS, TLS ClientHello), the
capsules of the TCP fallback, the relay framing. Go's bounds checks turn a
parser bug into a crash rather than code execution, and a per-packet guard
turns the crash into a dropped packet (R129). Privilege separation is the
next line: should a bug still give someone code execution, it happens in a
process that has neither the device key nor root.

```
                  root (parent)                          uid 65531 (worker)
  ┌───────────────────────────────────┐        ┌──────────────────────────────────┐
  │ device key (softkey file, TPM)    │ sign   │ control channel, snapshots       │
  │ netcfg + journal: TUN, routes,    │◀──────▶│ tunnels, paths, relay            │
  │   bypass, forwarding, NAT         │ socket │ every packet: parsers, flows,    │
  │ the local socket's place          │  pair  │   ACL, DNS learning              │
  │ restarts the worker, cleans up    │        │ the local socket (boundgatectl)  │
  └───────────────────────────────────┘        └──────────────────────────────────┘
          TUN device ──── passed as a descriptor ────▶ read and written here
```

Linux only for now. Turned on per node in `node.yaml`:

```yaml
privsep:
  user: "65531"        # a name, or uid[:gid]; never root
```

## What the parent does, and what it refuses

The parent reads the configuration, opens the device key and the host's
network configurator (with its cleanup journal, `netstate.json`), creates
the local socket (`/run/boundgate/node.sock`, 0660, `socket_group`), and
starts `boundgate-node privsep-worker` as the configured user with a
socket pair (fd 3) and the listening socket (fd 4). The worker gets its
configuration and the device key's public half from the parent, and runs
the node as it would run alone, with two replacements:

| The node needs | Without separation | With it |
|---|---|---|
| a TLS signature with the device key | the key in the process | `sign`: the parent signs a SHA-256/384/512 digest; the private key never enters the worker |
| the TUN device | opens `/dev/net/tun` | `create_tun`: the parent creates the configured device (`tun_name`, default `bg0`) and passes its descriptor |
| address, routes | `ip addr/route` | `set_address`, `add_route`, `del_route`: only on that device, only network prefixes |
| host routes to control plane, hubs, IdP | `ip route replace <host>` | `add_bypass`, `del_bypass`: unicast host addresses only |
| forwarding, NAT, forward rules, reply via arrival | `sysctl`, `nft` | the same operations, only for that device, NAT only for a pool in a private or shared range (the rule for the overlay pool) |
| a hub's listener on 443 | root | the one capability `CAP_NET_BIND_SERVICE` (ambient), when the parent has it |

Every refusal is logged by the parent (`privsep: refused a request of the
worker`). Everything else the node does needs no privileges and stays in
the worker: sockets, the netlink watch of the machine's networks, the state
files, the logs.

When the worker ends (a crash, a kill), the parent undoes what the journal
holds (bypass routes, NAT and forward rules, the arrival table; the device
and its routes went with the worker) and starts it again, after 1 s, then
doubling up to 30 s. When the parent ends, the kernel ends the worker
(`PR_SET_PDEATHSIG`).

## Files

The state directory belongs to the worker once separation is on: the parent
hands it over on its first start (owner the worker, group root, mode 0770),
with everything in it except its own files:

| File | Owner | |
|---|---|---|
| `device.key`, `device.tpm` | root, 0600 | the device key (or the TPM key blob); the worker cannot read it |
| `netstate.json` | root, 0600 | the parent's cleanup journal |
| everything else (`device.crt`, `control.pin`, `admin_trust.json`, `bindings_seen.json`, `settings.json`, `update/`) | the worker | |

The hand-over happens only while the directory still belongs to root, so the
parent never follows anything the worker could have placed there. Its own
files it reads only as plain files of root with one name, and writes through
a fresh file that is renamed into place (`internal/safefile`): a link the
worker puts there is replaced, never followed. The log directory is handed
over the same way. To go back to one process, remove `privsep` from
`node.yaml` and give the directories back to root (`chown -R 0:0`): root in
the kits' containers has no `DAC_OVERRIDE` and does not read the worker's
files; a root service outside a container does.

## What a compromised worker still can do

- use the key as a signer while it runs, and act as this node in the
  overlay: its tunnels, what its roles and the policies allow;
- route any network into the node's own device, add host routes that bypass
  it, turn on forwarding, masquerade the (private or shared) pool: what a full-tunnel
  profile or an exit node does legitimately anyway;
- rewrite its own state: the pinned control-plane key and the admin key
  list take effect at the next start. The parent does not check them yet;
- delete the parent's files (a new key on the next start: a denial of
  service, not a way in), or chmod its directory away from the parent;
- reach the host's network as an ordinary user.

It can no longer: read or copy the device key, change another interface's
addresses or routes, change the host's firewall beyond the node's own
rules, load kernel modules, read other users' files, or keep anything of
root when the parent restarts it.

## Containers

The kits (node, and the hub of all-in-one) add what the parent needs to
start and stop the worker and hand over its directories: `cap_add:
[NET_ADMIN, NET_BIND_SERVICE, SETUID, SETGID, CHOWN, KILL]` (the hub behind
the mux without `NET_BIND_SERVICE`). A parent that lacks one of the last
four does not start (`privsep: the service lacks the capabilities …`):
without `KILL` it could not stop a worker that runs as another user. The
worker itself ends up with no capability except `NET_BIND_SERVICE`, and
`no-new-privileges` stays on: the parent changes users with `setuid`, it
does not need a setuid binary.

The lab tests this in `deploy/compose/e2e.sh` step 2c on tmpfs with exactly
these capabilities (the lab's other state directories are the Mac's, shared
into the VM, and keep no owners): the key is root's, uid 65531 cannot read
it, a worker killed by its own user is started again, and a parent without
`KILL` refuses to start.

## Not yet

- seccomp and Landlock for the worker (no `execve`, no kernel attack surface
  it does not need, file access limited to its state and logs).
- The parent verifying pins and the admin key list before the worker may
  change them.
- macOS: the same split with the utun descriptor; Windows keeps one service
  process (Wintun's rings belong to the process that opened them) and is
  hardened instead.
