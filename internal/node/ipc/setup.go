package ipc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/update"
	"net"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/node"
)

// StateUnconfigured is the status state of a daemon that does not know its
// control plane yet (setup mode).
const StateUnconfigured node.State = "unconfigured"

// Settings is what a user may decide locally instead of the configuration
// file: which control plane this node belongs to. It is stored in
// <state_dir>/settings.json and only read when the file names none.
type Settings struct {
	ControlAddr       string `json:"control_addr"`
	ControlServerName string `json:"control_server_name,omitempty"`
	Name              string `json:"name,omitempty"`
}

// Validate normalizes and checks the settings.
func (s *Settings) Validate() error {
	s.ControlAddr = strings.TrimSpace(s.ControlAddr)
	s.ControlServerName = strings.TrimSpace(s.ControlServerName)
	s.Name = strings.TrimSpace(s.Name)
	s.ControlAddr = strings.TrimSuffix(strings.TrimPrefix(s.ControlAddr, "https://"), "/")
	if s.ControlAddr == "" {
		return errors.New("control plane address is required")
	}
	host, port := s.ControlAddr, ""
	if h, p, err := net.SplitHostPort(s.ControlAddr); err == nil {
		host, port = h, p
	}
	if host == "" || strings.ContainsAny(host, " /@?#") {
		return fmt.Errorf("%q is not a host name or address", s.ControlAddr)
	}
	if port != "" {
		if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
			return fmt.Errorf("invalid port %q", port)
		}
	}
	if len(s.Name) > 64 || len(s.ControlServerName) > 253 {
		return errors.New("value too long")
	}
	return nil
}

// LoadSettings reads the settings file; a missing file is not an error.
func LoadSettings(path string) (Settings, error) {
	var s Settings
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	if err := json.Unmarshal(b, &s); err != nil {
		return Settings{}, fmt.Errorf("%s: %w", path, err)
	}
	return s, nil
}

// SaveSettings writes the settings file (0600).
func SaveSettings(path string, s Settings) error {
	b, _ := json.MarshalIndent(s, "", "  ")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// listen creates the socket: 0660, owned by root and, when group is set,
// that group (name or gid), so its members can drive the daemon without
// sudo. On a Mac that is "admin" for the app.
func listen(socketPath, group string) (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(socketPath), 0o755); err != nil {
		return nil, err
	}
	_ = os.Remove(socketPath)
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("ipc: listen %s: %w", socketPath, err)
	}
	if err := os.Chmod(socketPath, 0o660); err != nil {
		ln.Close()
		return nil, err
	}
	if group != "" {
		gid, err := strconv.Atoi(group)
		if err != nil {
			g, gerr := user.LookupGroup(group)
			if gerr != nil {
				ln.Close()
				return nil, fmt.Errorf("ipc: socket group: %w", gerr)
			}
			gid, _ = strconv.Atoi(g.Gid)
		}
		if err := os.Chown(socketPath, -1, gid); err != nil {
			ln.Close()
			return nil, fmt.Errorf("ipc: socket group %s: %w", group, err)
		}
	}
	return ln, nil
}

func serveMux(ctx context.Context, ln net.Listener, socketPath string, mux *http.ServeMux) error {
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
		_ = os.Remove(socketPath)
	}()
	err := srv.Serve(ln)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// ServeSetup runs the socket of a daemon without a control plane: status
// says "unconfigured", configure stores the settings, and updates work as
// they do on a node's socket (upd may be nil). It returns the settings once
// they are stored, or an error / ctx end.
func ServeSetup(ctx context.Context, socketPath, group string, status node.Status, upd *update.Service, save func(Settings) error) (Settings, error) {
	ln, err := listen(socketPath, group)
	if err != nil {
		return Settings{}, err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var mu sync.Mutex
	var got Settings
	mux := SetupHandler(status, upd, save, func(s Settings) {
		mu.Lock()
		got = s
		mu.Unlock()
		go func() { time.Sleep(100 * time.Millisecond); cancel() }() // answer first, then hand over to the node
	})
	if err := serveMux(ctx, ln, socketPath, mux); err != nil {
		return Settings{}, err
	}
	mu.Lock()
	defer mu.Unlock()
	return got, nil
}

// SetupHandler is the API of a node without a control plane (setup mode).
// onConfigured runs after the settings were stored and the answer written.
func SetupHandler(status node.Status, upd *update.Service, save func(Settings) error, onConfigured func(Settings)) *http.ServeMux {
	status.State = StateUnconfigured
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/status", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, http.StatusOK, status) })
	mux.HandleFunc("POST /v1/configure", func(w http.ResponseWriter, r *http.Request) {
		var s Settings
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&s); err != nil {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "invalid body"})
			return
		}
		if err := s.Validate(); err != nil {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: err.Error()})
			return
		}
		if err := save(s); err != nil {
			writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "configured"})
		onConfigured(s)
	})
	updateRoutes(mux, upd)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusConflict, ErrorResponse{Error: "this node has no control plane yet; run `boundgatectl configure -control HOST`"})
	})
	return mux
}

// Forget removes what ties a node to its control plane: the settings, the
// pinned control-plane key and the admin key list; with newIdentity the
// device key files as well. The next control plane sees a node that enrolls.
func Forget(stateDir, settingsPath string, newIdentity bool) error {
	files := []string{settingsPath, "control.pin", "admin_trust.json", "admin_keys"}
	if newIdentity {
		files = append(files, "device.key", "device.sekey", "device.tpm", "device.crt")
	}
	for _, f := range files {
		if !filepath.IsAbs(f) {
			f = filepath.Join(stateDir, f)
		}
		if err := os.Remove(f); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}
