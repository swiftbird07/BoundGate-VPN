//go:build linux && (amd64 || arm64)

package sandbox

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// A sandbox is for good, so every test of it is a process of its own: the
// test binary starts itself as a child that confines itself and says what
// it then can and cannot do.
const childEnv = "BOUNDGATE_SANDBOX_CHILD"

func TestMain(m *testing.M) {
	if what := os.Getenv(childEnv); what != "" {
		child(what)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func say(format string, args ...any) { fmt.Printf(format+"\n", args...) }

func child(what string) {
	dir := os.Getenv("BOUNDGATE_SANDBOX_DIR")
	port, _ := strconv.Atoi(os.Getenv("BOUNDGATE_SANDBOX_PORT"))
	mode := Enforce
	if what == "audit" {
		mode = Audit
	}
	rep, err := Apply(Policy{Mode: mode, ReadWrite: []string{filepath.Join(dir, "own")}, ReadOnly: []string{"/etc", filepath.Join(dir, "missing")}, BindTCP: []uint16{uint16(port)}})
	if err != nil {
		say("apply: %v", err)
		os.Exit(3)
	}
	say("report: %s", rep)
	say("landlock: %d", rep.Landlock)
	switch what {
	case "work":
		work(dir, port)
		refused(dir, port, rep)
	case "audit":
		var ru unix.Rusage // not on the list
		say("off the list: %v", unix.Getrusage(unix.RUSAGE_SELF, &ru))
		say("before exec")
		_ = syscall.Exec("/bin/true", []string{"true"}, nil)
		say("after exec")
	case "exec":
		say("before exec")
		_ = syscall.Exec("/bin/true", []string{"true"}, nil)
		say("after exec")
	case "executable-memory":
		say("before mmap")
		_, err := unix.Mmap(-1, 0, 4096, unix.PROT_READ|unix.PROT_WRITE|unix.PROT_EXEC, unix.MAP_ANON|unix.MAP_PRIVATE)
		say("after mmap: %v", err)
	}
}

// work is what the node does all day, in small.
func work(dir string, port int) {
	own := filepath.Join(dir, "own")
	// threads that did not exist when the filter was set
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			time.Sleep(10 * time.Millisecond)
			b := make([]byte, 1<<20)
			_, _ = rand.Read(b[:64])
		}()
	}
	wg.Wait()
	runtime.GC()
	say("threads: ok")

	err := os.WriteFile(filepath.Join(own, "a.tmp"), []byte("x"), 0o600)
	if err == nil {
		err = os.Rename(filepath.Join(own, "a.tmp"), filepath.Join(own, "a"))
	}
	if err == nil {
		err = os.MkdirAll(filepath.Join(own, "sub", "dir"), 0o700)
	}
	if err == nil {
		_, err = os.ReadDir(own)
	}
	if err == nil {
		var f *os.File
		if f, err = os.OpenFile(filepath.Join(own, "log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640); err == nil {
			_, err = f.WriteString("line\n")
			if err == nil {
				err = f.Sync()
			}
			if err == nil {
				err = f.Truncate(0)
			}
			f.Close()
		}
	}
	if err == nil {
		err = os.Remove(filepath.Join(own, "a"))
	}
	say("own files: %v", err)

	_, err = os.ReadFile("/etc/hosts")
	say("read /etc/hosts: %v", err)
	_, err = os.Hostname()
	say("hostname: %v", err)
	_, err = net.Interfaces()
	say("interfaces: %v", err)

	// UDP and TCP over loopback
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err == nil {
		defer pc.Close()
		var c net.Conn
		if c, err = net.Dial("udp", pc.LocalAddr().String()); err == nil {
			defer c.Close()
			if _, err = c.Write([]byte("ping")); err == nil {
				buf := make([]byte, 16)
				_ = pc.SetReadDeadline(time.Now().Add(5 * time.Second))
				_, _, err = pc.ReadFrom(buf)
			}
		}
	}
	say("udp: %v", err)
	ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err == nil {
		defer ln.Close()
		go func() {
			if c, err := ln.Accept(); err == nil {
				_, _ = c.Write([]byte("pong"))
				c.Close()
			}
		}()
		var c net.Conn
		if c, err = net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second); err == nil {
			buf := make([]byte, 4)
			_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
			_, err = c.Read(buf)
			c.Close()
		}
	}
	say("tcp: %v", err)
	// a signal to itself is the runtime's own business (and terminateSelf's)
	say("signal to itself: %v", syscall.Kill(os.Getpid(), syscall.SIGURG))
}

// refused is what the sandbox is for.
func refused(dir string, port int, rep Report) {
	_, err := os.ReadFile(filepath.Join(dir, "outside", "secret"))
	say("read outside: %v", errors.Is(err, os.ErrPermission))
	err = os.WriteFile(filepath.Join(dir, "outside", "new"), []byte("x"), 0o600)
	say("write outside: %v", errors.Is(err, os.ErrPermission))
	err = os.WriteFile("/etc/boundgate-sandbox-test", []byte("x"), 0o600)
	say("write where it reads: %v", err != nil)
	err = os.Symlink("/etc/passwd", filepath.Join(dir, "own", "link"))
	say("a link in its own directory: %v", err != nil)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err == nil {
		ln.Close()
	}
	say("listen on another port: %v", errors.Is(err, os.ErrPermission))
	_, err = unix.Socket(unix.AF_INET, unix.SOCK_STREAM, unix.IPPROTO_MPTCP)
	say("MPTCP socket: %v", err)

	_, err = unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, 0)
	say("packet socket: %v", err)
	_, err = unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_NETFILTER)
	say("netfilter socket: %v", err)
	say("signal to the parent: %v", syscall.Kill(os.Getppid(), 0))
	say("start a program: %v", exec.Command("/bin/true").Run() != nil)
	var ru unix.Rusage
	say("off the list: %v", unix.Getrusage(unix.RUSAGE_SELF, &ru))
	say("another filter: %v", unix.Prctl(unix.PR_SET_DUMPABLE, 1, 0, 0, 0))
}

func run(t *testing.T, what string) (out string, state *os.ProcessState) {
	t.Helper()
	if withCgo {
		t.Skip("a build with cgo: the sandbox is for the release's builds, without")
	}
	dir := t.TempDir()
	for _, d := range []string{"own", "outside"} {
		if err := os.Mkdir(filepath.Join(dir, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "outside", "secret"), []byte("s"), 0o600); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(), childEnv+"="+what, "BOUNDGATE_SANDBOX_DIR="+dir, "BOUNDGATE_SANDBOX_PORT="+strconv.Itoa(port))
	var buf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &buf, &buf
	_ = cmd.Run()
	out = buf.String()
	t.Logf("%s:\n%s", what, out)
	if strings.Contains(out, "apply: ") && (strings.Contains(out, "operation not permitted") || strings.Contains(out, "function not implemented")) {
		t.Skip("this environment lets no process set a seccomp filter")
	}
	return out, cmd.ProcessState
}

func has(t *testing.T, out string, lines ...string) {
	t.Helper()
	for _, l := range lines {
		if !strings.Contains(out, l+"\n") {
			t.Errorf("missing: %q", l)
		}
	}
}

func TestTheNodesWorkGoesOn(t *testing.T) {
	out, state := run(t, "work")
	if !state.Success() {
		t.Fatalf("the child ended with %v", state)
	}
	has(t, out, "threads: ok", "own files: <nil>", "hostname: <nil>", "interfaces: <nil>", "udp: <nil>", "tcp: <nil>", "signal to itself: <nil>")
	if _, err := os.Stat("/etc/hosts"); err == nil {
		has(t, out, "read /etc/hosts: <nil>")
	}
	if !strings.Contains(out, "report: seccomp (") {
		t.Error("no seccomp filter in the report")
	}
}

func TestWhatTheSandboxRefuses(t *testing.T) {
	out, _ := run(t, "work")
	has(t, out,
		"packet socket: address family not supported by protocol",
		"MPTCP socket: protocol not supported",
		"a link in its own directory: true",
		"netfilter socket: address family not supported by protocol",
		"signal to the parent: operation not permitted",
		"start a program: true",
		"off the list: function not implemented",
		"another filter: operation not permitted",
		"write where it reads: true")
	if strings.Contains(out, "landlock: 0\n") {
		t.Log("no Landlock here: the file rules are not tested")
		return
	}
	has(t, out, "read outside: true", "write outside: true")
	if !strings.Contains(out, "landlock: 1\n") && !strings.Contains(out, "landlock: 2\n") && !strings.Contains(out, "landlock: 3\n") {
		has(t, out, "listen on another port: true")
	}
}

func killed(t *testing.T, state *os.ProcessState) {
	t.Helper()
	ws, ok := state.Sys().(syscall.WaitStatus)
	if !ok || !ws.Signaled() || ws.Signal() != syscall.SIGSYS {
		t.Fatalf("the child was not ended by the filter: %v", state)
	}
}

func TestStartingAProgramEndsTheProcess(t *testing.T) {
	out, state := run(t, "exec")
	has(t, out, "before exec")
	killed(t, state)
	if strings.Contains(out, "after exec") {
		t.Error("the process went on")
	}
}

func TestExecutableMemoryEndsTheProcess(t *testing.T) {
	out, state := run(t, "executable-memory")
	has(t, out, "before mmap")
	killed(t, state)
}

func TestAuditLetsThroughAndStillEndsExec(t *testing.T) {
	out, state := run(t, "audit")
	has(t, out, "off the list: <nil>", "before exec")
	killed(t, state)
}
