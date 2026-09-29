//go:build linux

package main

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/anchors"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/node"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/node/ipc"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/node/netcfg"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/privsep"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/sandbox"
)

// workerArg starts the worker of privilege separation (docs/PRIVSEP.md);
// only the parent passes it.
const workerArg = "privsep-worker"

// The parent's own files in the state directory: they stay root's when the
// rest of the directory goes to the worker, and the parent reads them only
// as its own (internal/safefile). The key and the journal are for the
// parent alone; the anchors (the control plane's pin, the admin key list,
// the binding history) the worker reads and only the parent writes.
var parentFiles = func() map[string]bool {
	m := map[string]bool{"device.key": true, "device.tpm": true, "netstate.json": true}
	for _, n := range anchors.Names {
		m[n] = true
	}
	return m
}()

// runPrivileged is the parent: it opens the device key, sets up the host's
// network and the local socket, and runs the node in a worker as
// cfg.Privsep.User, which asks for signatures and network changes over a
// socket pair. A worker that ends is started again after what it left on
// the host is undone.
func runPrivileged(ctx context.Context, raw []byte, cfg config) error {
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil)).With("component", "privsep")
	if os.Geteuid() != 0 {
		return errors.New("privsep: the service must start as root to hand the node to an unprivileged user; remove privsep from the configuration to run it as this user")
	}
	uid, gid, err := workerUser(cfg.Privsep.User)
	if err != nil {
		return err
	}
	if err := parentCapabilities(); err != nil {
		return err
	}
	if _, err := sandbox.ParseMode(cfg.Privsep.Sandbox); err != nil {
		return fmt.Errorf("privsep.%w", err)
	}
	if cfg.Control.Addr == "" {
		// without it the node asks at its local socket which control plane
		// to take (boundgatectl configure, reset), and that socket is the
		// worker's: the worker would choose whom the node trusts
		return errors.New("privsep: the control plane must be named in the configuration (control.addr); a separated node does not take it from its local socket")
	}
	if err := shareState(cfg.StateDir, uid, gid, parentFiles, log); err != nil {
		return err
	}
	if cfg.LogDir != "" {
		if err := handOver(cfg.LogDir, uid, nil, log); err != nil {
			return err
		}
	}
	trusted, err := anchors.Open(anchors.Options{Dir: cfg.StateDir, Pin: cfg.Control.Pin, Genesis: cfg.Control.SignersGenesis, Owner: -1, Shared: true})
	if err != nil {
		return fmt.Errorf("privsep: %w", err)
	}
	key, err := node.OpenDeviceKey(node.Config{StateDir: cfg.StateDir, KeyKind: cfg.KeyKind, TPMDevice: cfg.TPMDevice, SEKeyHelper: cfg.SEKeyHelper, Log: log})
	if err != nil {
		return err
	}
	journal := netcfg.NewJournal(netcfg.New(), filepath.Join(cfg.StateDir, "netstate.json"))
	cleanUp(ctx, journal, log)
	ln, err := ipc.Listen(cfg.Socket, cfg.SocketGroup, cfg.SocketUsers)
	if err != nil {
		return err
	}
	ul := ln.(*net.UnixListener)
	ul.SetUnlinkOnClose(false)
	socket, err := ul.File()
	ln.Close()
	if err != nil {
		return err
	}
	defer socket.Close()
	defer os.Remove(cfg.Socket)
	tunName := cfg.TUNName
	if tunName == "" {
		tunName = "bg0"
	}
	log.Info("privilege separation: the node runs as an unprivileged worker", "uid", uid, "gid", gid, "key_kind", key.Kind())

	backoff := time.Second
	for {
		started := time.Now()
		p := &privsep.Parent{Key: key, Net: journal, Config: raw, TUNName: tunName, WorkerUID: uid, Anchors: trusted, Log: log}
		err := superviseWorker(ctx, p, uid, gid, socket)
		// the worker's device went with it; the host routes and NAT rules it
		// asked for did not
		cleanUp(context.Background(), journal, log)
		if ctx.Err() != nil {
			return nil
		}
		if time.Since(started) > time.Minute {
			backoff = time.Second
		}
		log.Error("privsep: the worker ended; starting it again", "err", err, "in", backoff)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(backoff):
		}
		backoff = min(2*backoff, 30*time.Second)
	}
}

// superviseWorker runs one worker until it ends or ctx does.
func superviseWorker(ctx context.Context, p *privsep.Parent, uid, gid int, socket *os.File) error {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("privsep: socket pair: %w", err)
	}
	parentEnd, workerEnd := os.NewFile(uintptr(fds[0]), "privsep"), os.NewFile(uintptr(fds[1]), "privsep-worker")
	c, err := net.FileConn(parentEnd)
	parentEnd.Close()
	if err != nil {
		workerEnd.Close()
		return err
	}
	conn := c.(*net.UnixConn)
	defer conn.Close()

	cmd := exec.Command("/proc/self/exe", workerArg)
	cmd.Args[0] = "boundgate-node"
	cmd.Dir = "/"
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	cmd.ExtraFiles = []*os.File{workerEnd, socket} // fd 3 and 4
	attr := &syscall.SysProcAttr{
		Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), Groups: []uint32{}},
		Pdeathsig:  syscall.SIGKILL,
	}
	// a hub listens on 443: that one capability, and only when this process
	// has it to give
	if hasCapability(unix.CAP_NET_BIND_SERVICE) {
		attr.AmbientCaps = []uintptr{unix.CAP_NET_BIND_SERVICE}
	}
	cmd.SysProcAttr = attr
	err = cmd.Start()
	workerEnd.Close()
	if err != nil {
		return fmt.Errorf("privsep: start the worker: %w", err)
	}
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	served := make(chan error, 1)
	go func() { served <- p.Serve(sctx, conn) }()
	waited := make(chan error, 1)
	go func() { waited <- cmd.Wait() }()
	select {
	case err := <-waited:
		cancel()
		<-served
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			if ws, ok := exit.Sys().(syscall.WaitStatus); ok && ws.Signaled() && ws.Signal() == syscall.SIGSYS {
				// execve, ptrace, executable memory: the node does none of it
				p.Log.Error("privsep: the worker was ended by its sandbox for a system call the node never makes. This is what an attack on the node looks like; the kernel's log names the call (dmesg, type=1326 sig=31)", "pid", cmd.Process.Pid)
			}
		}
		return fmt.Errorf("worker: %v", err)
	case err := <-served:
		// the worker broke the protocol or closed its end: it goes
		_ = cmd.Process.Kill()
		<-waited
		if err == nil {
			err = errors.New("the worker closed the socket")
		}
		return err
	case <-ctx.Done():
		_ = cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-waited:
		case <-time.After(15 * time.Second):
			_ = cmd.Process.Kill()
			<-waited
		}
		cancel()
		<-served
		return nil
	}
}

// cleanUp undoes what the journal holds: bypass routes, NAT and forward
// rules, the arrival table.
func cleanUp(ctx context.Context, j *netcfg.Journal, log *slog.Logger) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if n := j.Recover(ctx); n > 0 {
		log.Warn("removed network leftovers of the worker", "entries", n)
	}
}

// workerUser resolves the configured user: a name, or uid[:gid].
func workerUser(spec string) (uid, gid int, err error) {
	if u, g, ok := strings.Cut(spec, ":"); ok || isNumber(spec) {
		if uid, err = strconv.Atoi(u); err != nil {
			return 0, 0, fmt.Errorf("privsep.user %q: %w", spec, err)
		}
		gid = uid
		if ok {
			if gid, err = strconv.Atoi(g); err != nil {
				return 0, 0, fmt.Errorf("privsep.user %q: %w", spec, err)
			}
		}
	} else {
		u, err := user.Lookup(spec)
		if err != nil {
			return 0, 0, fmt.Errorf("privsep.user: %w", err)
		}
		uid, _ = strconv.Atoi(u.Uid)
		gid, _ = strconv.Atoi(u.Gid)
	}
	if uid <= 0 || gid <= 0 {
		return 0, 0, fmt.Errorf("privsep.user %q: the worker must not run as root or with root's group", spec)
	}
	return uid, gid, nil
}

func isNumber(s string) bool {
	_, err := strconv.Atoi(s)
	return err == nil
}

// shareState makes the state directory one that parent and worker both
// write to and neither takes from the other: it stays root's, its group
// becomes the worker's with the right to write, and it is sticky, so that a
// file is removed or renamed only by its owner (as in /tmp). The worker
// keeps its own files there; the parent's (keep) it can read where they are
// readable, and neither remove nor replace. What is in the directory,
// except keep, goes to the worker once, while everything in it is still
// root's.
func shareState(dir string, uid, gid int, keep map[string]bool, log *slog.Logger) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || !fi.IsDir() {
		return fmt.Errorf("privsep: %s is not a directory", dir)
	}
	const shared = os.ModeDir | os.ModeSticky | 0o770
	switch {
	case st.Uid != 0:
		return fmt.Errorf("privsep: %s belongs to uid %d. The state directory is root's, also with privilege separation: give it back (chown -R 0:0 %s) and start again; what is the worker's in it goes to the worker then", dir, st.Uid, dir)
	case int(st.Gid) == gid && fi.Mode() == shared:
		return nil
	case st.Gid != 0:
		return fmt.Errorf("privsep: %s belongs to group %d, neither root's nor the worker's (%d); chown -R 0:0 %s and start again", dir, st.Gid, gid, dir)
	}
	n := 0
	err = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || path == dir {
			return err
		}
		if rel, _ := filepath.Rel(dir, path); keep[rel] {
			return nil
		}
		if info, err := d.Info(); err == nil && info.Mode().IsRegular() {
			if s, ok := info.Sys().(*syscall.Stat_t); ok && s.Nlink > 1 {
				// another name of it may be a file that must stay root's
				log.Warn("privsep: a file with several names stays root's", "path", path)
				return nil
			}
		}
		n++
		return os.Lchown(path, uid, gid) // WalkDir does not follow links, Lchown does not either
	})
	if err != nil {
		return fmt.Errorf("privsep: hand the files in %s to the worker: %w", dir, err)
	}
	if err := os.Chown(dir, 0, gid); err != nil {
		return fmt.Errorf("privsep: share %s with the worker: %w", dir, err)
	}
	if err := os.Chmod(dir, shared.Perm()|os.ModeSticky); err != nil {
		return fmt.Errorf("privsep: share %s with the worker: %w", dir, err)
	}
	// a file system that keeps no owners (a directory shared from another
	// machine, FAT) takes all of this and changes nothing
	fi, err = os.Lstat(dir)
	if err != nil {
		return err
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); !ok || st.Uid != 0 || int(st.Gid) != gid || fi.Mode() != shared {
		return fmt.Errorf("privsep: the file system of %s does not keep owners and permissions; privilege separation rests on them and needs a state directory that does", dir)
	}
	log.Info("the state directory is shared with the worker", "dir", dir, "gid", gid, "entries", n)
	return nil
}

// handOver gives dir to the worker, once: owner the worker, group root
// (the parent reaches it through the group, also without DAC override in
// a container), mode 0770, and everything in it except keep. Only a
// directory that still belongs to root is changed: nothing the worker ever
// had is followed as root again. The parent's own files stay root's.
func handOver(dir string, uid int, keep map[string]bool, log *slog.Logger) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || !fi.IsDir() {
		return fmt.Errorf("privsep: %s is not a directory", dir)
	}
	switch int(st.Uid) {
	case uid:
		return nil
	case 0:
	default:
		return fmt.Errorf("privsep: %s belongs to uid %d, neither to root nor to the worker (uid %d)", dir, st.Uid, uid)
	}
	n := 0
	err = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || path == dir {
			return err
		}
		if rel, _ := filepath.Rel(dir, path); keep[rel] {
			return nil
		}
		n++
		return os.Lchown(path, uid, 0) // WalkDir does not follow links, Lchown does not either
	})
	if err != nil {
		return fmt.Errorf("privsep: hand %s to the worker: %w", dir, err)
	}
	// the mode first: once the directory is the worker's, only CAP_FOWNER
	// could change it, and the node kit does not give the parent that
	if err := os.Chmod(dir, 0o770); err != nil {
		return err
	}
	if err := os.Chown(dir, uid, 0); err != nil {
		return fmt.Errorf("privsep: hand %s to the worker: %w", dir, err)
	}
	log.Info("handed a directory to the worker", "dir", dir, "uid", uid, "entries", n)
	return nil
}

// hasCapability reports whether this process has c in its permitted and
// effective sets.
func hasCapability(c int) bool {
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if err := unix.Capget(&hdr, &data[0]); err != nil {
		return false
	}
	bit := uint32(1) << (uint(c) % 32)
	return data[c/32].Permitted&bit != 0 && data[c/32].Effective&bit != 0
}

// parentCapabilities: what the parent needs besides NET_ADMIN, which a
// container without them (cap_drop: [ALL]) would only show later, as a worker
// that cannot start or a worker that cannot be stopped.
func parentCapabilities() error {
	var missing []string
	for _, c := range []struct {
		n    int
		name string
	}{
		{unix.CAP_SETUID, "SETUID"}, {unix.CAP_SETGID, "SETGID"}, // start the worker as its user
		{unix.CAP_CHOWN, "CHOWN"}, // hand it its directories
		{unix.CAP_KILL, "KILL"},   // end it: it runs as another user
	} {
		if !hasCapability(c.n) {
			missing = append(missing, c.name)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("privsep: the service lacks the capabilities %s (a container: add them to cap_add, docs/PRIVSEP.md)", strings.Join(missing, ", "))
	}
	return nil
}

// confine puts the worker into its sandbox (internal/sandbox): its state
// and its logs to write, the resolver's configuration to read, its own
// TCP port to listen on, and the system calls of a network daemon.
func confine(cfg config) (sandbox.Report, error) {
	mode, err := sandbox.ParseMode(cfg.Privsep.Sandbox)
	if err != nil {
		return sandbox.Report{}, err
	}
	if mode == sandbox.Off {
		return sandbox.Apply(sandbox.Policy{Mode: mode})
	}
	p := sandbox.Policy{Mode: mode, ReadWrite: []string{cfg.StateDir}}
	if cfg.LogDir != "" {
		p.ReadWrite = append(p.ReadWrite, cfg.LogDir)
	}
	// /etc as a directory, not its files: resolv.conf is replaced, not
	// rewritten, where something manages it, and a rule about a file is
	// about the file that was there
	p.ReadOnly = []string{"/etc", cfg.ProfilesDir, cfg.Update.TokenFile}
	if target, err := filepath.EvalSymlinks("/etc/resolv.conf"); err == nil && filepath.Dir(target) != "/etc" {
		p.ReadOnly = append(p.ReadOnly, filepath.Dir(target)) // /run/systemd/resolve and its like
	}
	if cfg.Listen != "" && (cfg.TCPFallback == nil || *cfg.TCPFallback) {
		if _, port, err := net.SplitHostPort(cfg.Listen); err == nil {
			if n, err := net.LookupPort("tcp", port); err == nil && n > 0 {
				p.BindTCP = append(p.BindTCP, uint16(n))
			}
		}
	}
	readOnce()
	return sandbox.Apply(p)
}

// readOnce has Go's library read now what it reads once and keeps: the
// CA roots (the release check is the one connection that asks the
// system's), the time zone, the kernel's limit for a listener's queue.
// What is in memory needs no rule in the sandbox.
func readOnce() {
	_, _ = x509.SystemCertPool()
	_ = time.Now().Local().String()
	if ln, err := net.Listen("tcp", "127.0.0.1:0"); err == nil {
		ln.Close()
	}
}

// runWorker is the worker: fd 3 is its end of the socket pair, fd 4 the
// local socket the parent made. It never runs as root.
func runWorker() int {
	if os.Geteuid() == 0 {
		fmt.Fprintln(os.Stderr, "boundgate-node: the privsep worker does not run as root")
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	c, err := privsep.Dial(os.NewFile(3, "privsep"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "boundgate-node:", err)
		return 1
	}
	hctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	h, key, err := c.Hello(hctx)
	cancel()
	if err != nil {
		fmt.Fprintln(os.Stderr, "boundgate-node:", err)
		return 1
	}
	cfg, err := parseConfig(h.Config)
	if err != nil {
		fmt.Fprintln(os.Stderr, "boundgate-node:", err)
		return 1
	}
	ctx, cancel = context.WithCancel(ctx)
	defer cancel()
	go func() {
		<-c.Done()
		cancel()
	}()
	hostNet, err := c.Net()
	if err != nil {
		fmt.Fprintln(os.Stderr, "boundgate-node:", err)
		return 1
	}
	trusted, err := c.Anchors(cfg.StateDir, h.ParentUID, anchors.Options{Pin: cfg.Control.Pin, Genesis: cfg.Control.SignersGenesis})
	if err != nil {
		fmt.Fprintln(os.Stderr, "boundgate-node:", err)
		return 1
	}
	// from here on the worker talks to the network: it confines itself first
	confined, err := confine(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "boundgate-node:", err, "(privsep.sandbox: off runs the worker without)")
		return 1
	}
	sep := &separated{key: key, net: hostNet, anchors: trusted, socket: os.NewFile(4, "node.sock"), uid: os.Getuid(),
		sandbox: confined.String(), incomplete: confined.Missing}
	if err := runWith(ctx, cfg, sep); err != nil {
		fmt.Fprintln(os.Stderr, "boundgate-node:", err)
		return 1
	}
	return 0
}
