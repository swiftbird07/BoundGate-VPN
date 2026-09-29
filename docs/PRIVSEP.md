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
  └───────────────────────────────────┘        └───── in a sandbox: seccomp, ─────┘
                                                      Landlock (below)
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
root when the parent restarts it. With the sandbox (below) it can neither
start a program nor make memory executable, reads and writes no file
outside its state, its logs and `/etc`, signals no other process, and
reaches the kernel through some 80 system calls instead of 400.

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

## The worker's sandbox

Before the worker reads anything from the network it confines itself, for
good (`internal/sandbox`). Two mechanisms of the kernel, neither of which
the worker can take back, and both on every thread:

**seccomp**: a filter over the system calls.

| A call | |
|---|---|
| on the list (about 80: threads, memory, timers, signals, sockets, files) | goes through |
| `execve`, `execveat`, `ptrace`, `process_vm_readv`, `process_vm_writev` | ends the worker (SIGSYS). The node starts no program and looks into no other process: whoever asks is not the node |
| `mmap`, `mprotect` with `PROT_EXEC` | ends the worker. Memory that was written and is then executed is how injected code runs; a Go program without cgo never asks for it |
| `clone` | threads only; a new process is refused |
| `kill`, `tgkill` | to the worker itself only |
| `socket` | unix sockets, TCP and UDP over IPv4 and IPv6, netlink's routing protocol (reading the machine's networks). No packet or raw sockets, no other netlink protocol, no SCTP, no MPTCP |
| `ioctl` | the tunnel device's name and offloads, an interface's index and MTU |
| `prctl` | naming memory regions (the Go runtime) |
| another instruction set (32-bit, x32) | ends the worker |
| everything else (`mount`, `setuid`, `bpf`, `io_uring`, `keyctl`, `unshare`, `perf_event_open`, `userfaultfd`, the module calls, …) | fails with "function not implemented" and is written to the kernel's log |

**Landlock**: a domain over files and listening ports.

| | |
|---|---|
| `state_dir`, `log_dir` | plain files and directories: read, write, create, remove. Nothing is executed, no device, socket or link is made |
| `/etc`, `profiles_dir`, where `/etc/resolv.conf` points to | read (the resolver's configuration, the profiles) |
| everything else (`/proc`, `/sys`, `/tmp`, `/home`, the host's other files) | neither read nor written |
| TCP | listening only on the port of `listen` (a hub with the TCP fallback), on none otherwise |

What the worker has open when it enters stays open: the socket pair to the
parent, the local socket, the routing tables it watches; the tunnel device
comes from the parent as a descriptor. CA roots and the time zone are read
before.

```yaml
privsep:
  user: "65531"
  sandbox: enforce     # the default. audit | off
```

`boundgatectl status` shows what applies (`sandbox: seccomp (82 system
calls), landlock v4`), and what is missing where something is: a kernel
without Landlock (before 5.13, or without the `landlock` security module)
still gets the filter, and says so; a machine that is neither amd64 nor
arm64 has no filter. Landlock's rules grow with the kernel: ports from
version 4 (Linux 6.7), device `ioctl` from 5, abstract unix sockets from 6.

**When the list lacks a call.** It was read from the sources of Go's runtime
and libraries and run against the lab; a new Go release or a rare path may
ask for one more. The kernel logs every refusal (`dmesg | grep type=1326`,
or the audit log: `syscall=` is the number, `code=0x5…` a refusal,
`code=0x7ffc0000` one that `audit` let through, `sig=31` a worker that was
ended). `sandbox: audit` lets through and only logs what the filter would refuse
(and executable memory), to find all of it at once; starting a program
still ends the worker, and the file rules stay as they are. `sandbox: off`
runs the worker without.
Both are in `node.yaml`, which the worker cannot write.

The tests: `internal/sandbox` confines a child process and has it try
(the node's work goes on; files outside, other ports, packet sockets,
signals to others and new programs are refused; `execve` and executable
memory end it), and runs the filter's logic on every platform against a
BPF machine in Go. `deploy/compose/e2e.sh` checks on three nodes that every
thread of the worker carries the filter, and runs everything else with the
sandbox on.

**What it does not do.** The worker still talks to the network as it
likes (UDP anywhere, TCP connections anywhere: where the hubs are is not
known before the control plane says it), still uses the key as a signer
while it runs, and still owns its state. The kernel remains reachable
through the calls on the list: a bug in the network stack, in `epoll` or
`futex` is not what a filter stops.

## Not yet

- The parent verifying pins and the admin key list before the worker may
  change them.
- macOS: the same split with the utun descriptor; Windows keeps one service
  process (Wintun's rings belong to the process that opened them) and is
  hardened instead.
