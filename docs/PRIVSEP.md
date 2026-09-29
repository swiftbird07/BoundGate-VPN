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
  │ what the node trusts: pin, admin  │        │                                  │
  │   key list, binding history       │        │                                  │
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
| to pin the control plane's key | writes `control.pin` | `pin_control`: only while no key is pinned |
| to follow the admin key list | writes `admin_trust.json` | `follow_signers`: the parent verifies the chain itself and moves only along links signed by a key of the list it holds |
| to remember bindings and revocations | writes `bindings_seen.json` | `record`: each entry with the signed binding or revocation that proves it; the parent verifies the signature and only ever moves forward |

Every refusal is logged by the parent (`privsep: refused a request of the
worker`). Everything else the node does needs no privileges and stays in
the worker: sockets, the netlink watch of the machine's networks, the state
files, the logs.

When the worker ends (a crash, a kill), the parent undoes what the journal
holds (bypass routes, NAT and forward rules, the arrival table; the device
and its routes went with the worker) and starts it again, after 1 s, then
doubling up to 30 s. When the parent ends, the kernel ends the worker
(`PR_SET_PDEATHSIG`).

## What the node trusts, and who may change it

Three things decide whom a node takes for its control plane and its
administrators after the next start: the control plane's pinned key, the
admin key list, and the newest binding and revocation it saw of every node.
A worker that could rewrite them would outlive itself: taken over once, it
would leave behind a node that trusts someone else's control plane and
someone else's signatures, also after the bug is fixed and the worker
started again.

They are the parent's. The worker reads them (none is a secret) and asks
for changes, and the parent decides by rules that need no trust in the
worker (`internal/anchors`, the same code a node in one process applies to
itself):

| | The rule | What a worker cannot do |
|---|---|---|
| `control.pin` | set once, while none is set | pin another control plane. The key changes when root removes the file and someone enrolls again |
| `admin_trust.json` | the first list is pinned (or must have the hash `control.signers_genesis` names); then only along links signed by a key of the list before. The parent verifies the signatures itself | replace the list, skip a link, go back |
| `bindings_seen.json` | an entry moves with the signed binding or revocation that proves it, verified against the list, and only forward | forget a revocation, make room for an older binding, invent a newer one |

What rests on trust is the first use, as everywhere: a node that pins on
first contact pins what it is shown. `control.pin` and
`control.signers_genesis` in `node.yaml` take that moment away; the file is
root's and the worker gets it read.

A separated node has its control plane in its configuration
(`control.addr`). The other way, `boundgatectl configure` and `reset` at the
local socket, would let the worker choose, since the socket is the
worker's: the parent does not start without.

The parent reads what the worker sends for this (chains, bindings,
signatures): Go's parsers for JSON and SSH signatures, which the fuzz tests
cover. Should one of them panic, the request fails and the parent stays.

## Files

The state directory stays root's. On its first start with separation the
parent shares it: group the worker's, mode 1770. The sticky bit is what
`/tmp` has: a file is removed or renamed by its owner only. So both write
there, and neither takes the other's files away:

| File | Owner | |
|---|---|---|
| `device.key`, `device.tpm` | root, 0600 | the device key (or the TPM key blob); the worker cannot read it |
| `netstate.json` | root, 0600 | the parent's cleanup journal |
| `control.pin`, `admin_trust.json`, `bindings_seen.json` | root, 0644 | what the node trusts; the worker reads them, as root's files only, and cannot write, remove or replace them |
| everything else (`device.crt`, `enrollment.json`, `reset.key`, `update/`) | the worker | |

What was in the directory goes to the worker once, while all of it is still
root's, except the files above. The parent reads its files only as plain
files of root with one name, and writes through a fresh file that is
renamed into place (`internal/safefile`); the worker reads the parent's the
same way, so a file of its own under such a name (left by a worker before
it) is refused, not believed. The log directory is the worker's (owner the
worker, group root, 0770). To go back to one process, remove `privsep` from
`node.yaml` and give the directories back to root (`chown -R 0:0`, and
`chmod 700` for the state): root in the kits' containers has no
`DAC_OVERRIDE` and does not read the worker's files; a root service outside
a container does.

## What a compromised worker still can do

- use the key as a signer while it runs, and act as this node in the
  overlay: its tunnels, what its roles and the policies allow;
- route any network into the node's own device, add host routes that bypass
  it, turn on forwarding, masquerade the (private or shared) pool: what a full-tunnel
  profile or an exit node does legitimately anyway;
- believe what it likes while it runs: what it holds in memory is its own.
  It ends with the worker, and the next one starts from the parent's files;
- rewrite what is its own in the state directory: `enrollment.json` (what
  the node last heard about its enrollment; the control plane says it again),
  `device.crt` (made from the key; a wrong one fails every handshake),
  `reset.key` (lets whoever knows it end this node's QUIC connections), the
  logs on disk (flow records are at the control plane by then);
- fill the state directory, or keep the node from working: a denial of
  service it has in many ways;
- reach the host's network as an ordinary user.

It can no longer: read or copy the device key, change another interface's
addresses or routes, change the host's firewall beyond the node's own
rules, load kernel modules, read other users' files, or keep anything of
root when the parent restarts it. It cannot change whom the node trusts:
not the control plane's key, not the admin keys, not what the node
remembers of revocations, and it can neither remove nor replace the
parent's files. With the sandbox (below) it can neither
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

- A sandbox for the parent itself. It starts `ip` and `nft`, so a filter
  for it is a filter for them; its input is the worker's requests.
- A worker that is ended by its sandbox is logged by the parent, not yet
  reported to the control plane.
- macOS: the same split with the utun descriptor; Windows keeps one service
  process (Wintun's rings belong to the process that opened them) and is
  hardened instead.
