package ipc

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/node"
)

// Several networks, one at a time.
//
// A device can belong to more than one mesh -- "Private" at home, "Work" at
// the company -- and each mesh is a control plane of its own that has to see
// a device key of its own (docs/SECURITY.md R142). So a network gets a
// directory of its own under <state>/networks/<id>, and node.Config.StateDir
// points there: key, pinned control plane, admin key list and enrollment all
// take the paths they always took, one set per network.
//
// The network that existed before this file keeps the state root as its
// directory. Nothing moves, the device key stays where it is, the fingerprint
// the control plane knows stays the same.
//
// One network runs at a time (the decision of 2026-10-20). A switch ends the
// running node first, so its routes are gone before the next one starts
// (R143), and the cleanup journal stays one for the whole daemon, in the
// state root, so leftovers are cleaned up whatever was running.
const networksFile = "networks.json"

// Network is one mesh this device belongs to.
type Network struct {
	// ID names it in the IPC and is the directory name of a network that
	// has one; it is a slug of the name and never changes.
	ID   string `json:"id"`
	Name string `json:"name"`
	// where its control plane is, and how this device calls itself there
	ControlAddr       string `json:"control_addr"`
	ControlServerName string `json:"control_server_name,omitempty"`
	NodeName          string `json:"node_name,omitempty"`
	// Dir is the state directory, relative to the state root. Empty means
	// the root itself: the network from before there were several.
	Dir string `json:"dir,omitempty"`
	// LastEnrollment is what the daemon last saw for this network
	// ("approved", "pending", ...), so the list says something about a
	// network that has no control channel right now.
	LastEnrollment string `json:"last_enrollment,omitempty"`
}

// Networks is <state>/networks.json.
type Networks struct {
	// Current is the ID of the network that runs; empty means none is
	// chosen yet (setup mode).
	Current string    `json:"current"`
	List    []Network `json:"networks"`
}

// Label is what to show: its name, or the address it was never named after.
func (n Network) Label() string {
	if n.Name != "" {
		return n.Name
	}
	return n.ControlAddr
}

// Settings of this network, as the daemon runs it.
func (n Network) Settings() Settings {
	return Settings{ControlAddr: n.ControlAddr, ControlServerName: n.ControlServerName, Name: n.NodeName}
}

// Path is where this network's state lives.
func (n Network) Path(stateDir string) string {
	if n.Dir == "" {
		return stateDir
	}
	return filepath.Join(stateDir, n.Dir)
}

// Prepare creates the network's directory (0700) and returns its path. The
// root network's directory is the daemon's own and already there.
func (n Network) Prepare(stateDir string) (string, error) {
	p := n.Path(stateDir)
	if err := os.MkdirAll(p, 0o700); err != nil {
		return "", err
	}
	return p, nil
}

// subDir is the only directory a network of its own may have: anything else
// in Dir means the file was edited by hand, and nothing is deleted there.
func (n Network) subDir() string { return filepath.Join("networks", n.ID) }

// Discard gives up a network's state, its device key included: the key
// belonged to that control plane and is of no use to anyone else, and the
// next network must not inherit it -- two control planes would see the same
// device (R142). A network with a directory of its own loses that directory.
// The network that owns the state root gives up what ties it to its control
// plane and its key files, and keeps the daemon's own files (the journal,
// the update work directory) where they are.
func (n Network) Discard(stateDir string) error {
	if n.Dir == "" {
		return Forget(stateDir, filepath.Join(stateDir, "settings.json"), true)
	}
	if filepath.Clean(n.Dir) != n.subDir() {
		return fmt.Errorf("network %q has the state directory %q, which this daemon did not create; remove it yourself", n.ID, n.Dir)
	}
	return os.RemoveAll(n.Path(stateDir))
}

// Create makes the directory of a network that was just added. A directory
// that is already there is not taken over: it is a network that was removed
// and could not be deleted, or something the daemon did not make, and its
// key would become this network's (R142). The root network has the daemon's
// state directory and nothing to create.
func (n Network) Create(stateDir string) error {
	if n.Dir == "" {
		return nil
	}
	p := n.Path(stateDir)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	if err := os.Mkdir(p, 0o700); err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("a state directory for network %q is still there (%s): remove it, or give the network another name", n.ID, p)
		}
		return err
	}
	return nil
}

// Find returns the index of a network, or -1.
func (ns *Networks) Find(id string) int {
	for i, n := range ns.List {
		if n.ID == id {
			return i
		}
	}
	return -1
}

// Get returns a network by ID.
func (ns *Networks) Get(id string) (Network, bool) {
	if i := ns.Find(id); i >= 0 {
		return ns.List[i], true
	}
	return Network{}, false
}

// CurrentNetwork is the network that runs.
func (ns *Networks) CurrentNetwork() (Network, bool) {
	if ns.Current == "" {
		return Network{}, false
	}
	return ns.Get(ns.Current)
}

// Add appends a network and returns it. The settings are validated; name
// falls back to the control plane's address.
//
// The first network of a daemon keeps the state root as its directory: a
// device with one network has the layout it always had, down to the
// settings file an older binary reads. Every later network gets
// <state>/networks/<id> of its own.
func (ns *Networks) Add(name string, s Settings) (Network, error) {
	if err := s.Validate(); err != nil {
		return Network{}, err
	}
	name = strings.TrimSpace(name)
	if name == "" {
		name = s.ControlAddr
	}
	if len(name) > 64 {
		return Network{}, errors.New("network name too long")
	}
	n := Network{ID: ns.freeID(name), Name: name, ControlAddr: s.ControlAddr, ControlServerName: s.ControlServerName, NodeName: s.Name}
	if len(ns.List) > 0 {
		n.Dir = n.subDir()
	}
	ns.List = append(ns.List, n)
	return n, nil
}

// Remove drops a network from the list. It does not touch its files; that is
// Discard, which the caller does first.
func (ns *Networks) Remove(id string) error {
	i := ns.Find(id)
	if i < 0 {
		return fmt.Errorf("no network %q", id)
	}
	ns.List = append(ns.List[:i], ns.List[i+1:]...)
	if ns.Current == id {
		ns.Current = ""
		if len(ns.List) > 0 {
			ns.Current = ns.List[0].ID // a daemon without a current network waits in setup mode
		}
	}
	return nil
}

// freeID is the slug of name, with a number appended while it is taken.
// The number takes the place of the slug's last characters when the slug
// is at its full length: the result has to be a slug itself, or validate
// refuses the file on the next start.
func (ns *Networks) freeID(name string) string {
	base := slug(name)
	id := base
	for i := 2; ns.Find(id) >= 0; i++ {
		num := strconv.Itoa(i)
		id = strings.TrimRight(base[:min(len(base), maxSlug-len(num))], "-") + num
	}
	return id
}

// maxSlug is the longest ID slug makes.
const maxSlug = 24

// slug makes an ID a user can type and a directory name that needs no
// quoting: lower case, letters, digits and dashes.
func slug(name string) string {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(name) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			dash = false
		default:
			if !dash && b.Len() > 0 {
				b.WriteByte('-')
				dash = true
			}
		}
		if b.Len() >= maxSlug {
			break
		}
	}
	s := strings.Trim(b.String(), "-")
	if s == "" {
		return "net"
	}
	return s
}

// LoadNetworks reads <stateDir>/networks.json. Without that file it builds
// the list from what is already there: a settings.json that names a control
// plane becomes the one network, with the state root as its directory. It
// reports whether it had to do that, so the caller can store the result.
func LoadNetworks(stateDir string) (*Networks, bool, error) {
	ns := &Networks{}
	path := filepath.Join(stateDir, networksFile)
	err := readJSONFile(path, ns)
	switch {
	case err == nil:
		if err := ns.validate(); err != nil {
			return nil, false, fmt.Errorf("%s: %w", path, err)
		}
		return ns, false, nil
	case !errors.Is(err, os.ErrNotExist):
		return nil, false, err
	}
	s, err := LoadSettings(filepath.Join(stateDir, "settings.json"))
	if err != nil {
		return nil, false, err
	}
	if s.ControlAddr == "" {
		return ns, false, nil // nothing configured yet: setup mode
	}
	n := Network{ID: slug(s.ControlAddr), Name: s.ControlAddr, ControlAddr: s.ControlAddr,
		ControlServerName: s.ControlServerName, NodeName: s.Name}
	ns.List = []Network{n}
	ns.Current = n.ID
	return ns, true, nil
}

// validate checks a file that someone may have edited.
func (ns *Networks) validate() error {
	seen := map[string]bool{}
	for i, n := range ns.List {
		if n.ID == "" || slug(n.ID) != n.ID {
			return fmt.Errorf("network %d has the id %q, which is not a name for a directory", i, n.ID)
		}
		if seen[n.ID] {
			return fmt.Errorf("two networks with the id %q", n.ID)
		}
		seen[n.ID] = true
		if n.Dir != "" && filepath.Clean(n.Dir) != n.subDir() {
			return fmt.Errorf("network %q points at %q instead of %q", n.ID, n.Dir, n.subDir())
		}
		s := n.Settings()
		if err := s.Validate(); err != nil {
			return fmt.Errorf("network %q: %w", n.ID, err)
		}
	}
	if ns.Current != "" && !seen[ns.Current] {
		return fmt.Errorf("the current network %q is not in the list", ns.Current)
	}
	return nil
}

// SaveNetworks writes <stateDir>/networks.json (0600, atomically).
func SaveNetworks(stateDir string, ns *Networks) error {
	return writeJSONFile(filepath.Join(stateDir, networksFile), ns)
}

// Networker is what a daemon that can hold several networks offers its
// socket. Add and Select only write down the choice; the daemon switches
// after the answer went out, because the switch closes the socket.
type Networker interface {
	// List is the networks and which one runs.
	List() (NetworkList, error)
	// Add stores a new network. With selectIt it becomes the current one,
	// coming up in profile (empty: it stays down until someone says up).
	Add(name string, s Settings, selectIt bool, profile string) (Network, error)
	// Select makes id the current network, coming up in profile.
	Select(id, profile string) error
	// Remove gives up a network and the state that belongs to it.
	Remove(id string) error
}

// NetworkList is the answer of GET /v1/networks.
type NetworkList struct {
	Current  string    `json:"current"`
	Networks []Network `json:"networks"`
	// Single, when set, says why this daemon runs this one network and
	// cannot be given another.
	Single string `json:"single,omitempty"`
}

// NewNetwork is the body of POST /v1/networks.
type NewNetwork struct {
	Name              string `json:"name"`
	ControlAddr       string `json:"control_addr"`
	ControlServerName string `json:"control_server_name,omitempty"`
	NodeName          string `json:"node_name,omitempty"`
	// Select switches to the new network right away, Profile is the routing
	// profile it should come up in.
	Select  bool   `json:"select,omitempty"`
	Profile string `json:"profile,omitempty"`
}

func (n NewNetwork) settings() Settings {
	return Settings{ControlAddr: n.ControlAddr, ControlServerName: n.ControlServerName, Name: n.NodeName}
}

// SelectRequest is the body of POST /v1/networks/{id}/select.
type SelectRequest struct {
	Profile string `json:"profile,omitempty"`
}

// networkRoutes serves the network endpoints. A daemon that runs a single
// network (its control plane in the configuration file, privilege
// separation, an app's packet tunnel) answers the list with that one network
// and refuses the rest with the reason.
func networkRoutes(mux *http.ServeMux, status func() node.Status, opt Options, onSwitch func()) {
	single := func(w http.ResponseWriter) bool {
		if opt.Nets != nil {
			return false
		}
		reason := opt.SingleNetwork
		if reason == "" {
			reason = "this daemon runs a single network"
		}
		writeJSON(w, http.StatusConflict, ErrorResponse{Error: reason})
		return true
	}
	mux.HandleFunc("GET /v1/networks", func(w http.ResponseWriter, r *http.Request) {
		if opt.Nets == nil {
			st := status()
			one := Network{ID: st.NetworkID, Name: st.Control, ControlAddr: st.Control, NodeName: st.NodeName, LastEnrollment: st.Enrollment}
			if one.ID == "" {
				one.ID = "default"
			}
			reason := opt.SingleNetwork
			if reason == "" {
				reason = "this daemon runs a single network"
			}
			writeJSON(w, http.StatusOK, NetworkList{Current: one.ID, Networks: []Network{one}, Single: reason})
			return
		}
		list, err := opt.Nets.List()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, list)
	})
	mux.HandleFunc("POST /v1/networks", func(w http.ResponseWriter, r *http.Request) {
		if single(w) {
			return
		}
		var req NewNetwork
		if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "invalid body"})
			return
		}
		if req.Select && !isDown(status) {
			writeJSON(w, http.StatusConflict, ErrorResponse{Error: "disconnect first (boundgatectl down), then switch"})
			return
		}
		net, err := opt.Nets.Add(req.Name, req.settings(), req.Select, req.Profile)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, net)
		if req.Select && onSwitch != nil {
			onSwitch()
		}
	})
	mux.HandleFunc("POST /v1/networks/{id}/select", func(w http.ResponseWriter, r *http.Request) {
		if single(w) {
			return
		}
		var req SelectRequest
		if r.ContentLength != 0 {
			if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
				writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "invalid body"})
				return
			}
		}
		// the old network's routes have to be gone before the new one adds
		// its own (R143), and that is what ending the node does
		if !isDown(status) {
			writeJSON(w, http.StatusConflict, ErrorResponse{Error: "disconnect first (boundgatectl down), then switch"})
			return
		}
		if err := opt.Nets.Select(r.PathValue("id"), req.Profile); err != nil {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "switching", "network": r.PathValue("id")})
		if onSwitch != nil {
			onSwitch()
		}
	})
	mux.HandleFunc("DELETE /v1/networks/{id}", func(w http.ResponseWriter, r *http.Request) {
		if single(w) {
			return
		}
		id := r.PathValue("id")
		list, err := opt.Nets.List()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
			return
		}
		if id == list.Current && !isDown(status) {
			writeJSON(w, http.StatusConflict, ErrorResponse{Error: "this is the network that runs; disconnect first (boundgatectl down)"})
			return
		}
		if err := opt.Nets.Remove(id); err != nil {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "removed", "network": id})
		if id == list.Current && onSwitch != nil {
			onSwitch() // the daemon has to leave this network behind
		}
	})
}

// isDown: nothing is up that would leave routes behind. A daemon in setup
// mode has no node at all and is down by definition.
func isDown(status func() node.Status) bool {
	st := status().State
	return st == node.StateDown || st == StateUnconfigured
}
