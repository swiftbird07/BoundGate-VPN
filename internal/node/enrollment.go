package node

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// enrollmentFile keeps the last enrollment state the control plane reported,
// so that a restart shows it at once. It decides nothing: bringing the
// overlay up still needs a snapshot, which the control plane gives only to
// approved nodes, and its next answer replaces the file.
const enrollmentFile = "enrollment.json"

type savedEnrollment struct {
	Status string `json:"status"`
	NodeID string `json:"node_id,omitempty"`
}

func loadEnrollment(dir string) (savedEnrollment, bool) {
	b, err := os.ReadFile(filepath.Join(dir, enrollmentFile))
	if err != nil {
		return savedEnrollment{}, false
	}
	var e savedEnrollment
	if json.Unmarshal(b, &e) != nil {
		return savedEnrollment{}, false
	}
	switch e.Status {
	case "pending", "confirmed", "approved", "revoked":
		return e, true
	}
	return savedEnrollment{}, false
}

// saveEnrollment writes the state when it changed. Caller holds n.mu.
func (n *Node) saveEnrollment() {
	e := savedEnrollment{Status: n.status.Enrollment, NodeID: string(n.status.NodeID)}
	if old, ok := loadEnrollment(n.cfg.StateDir); ok && old == e {
		return
	}
	if e.Status == "unknown" || e.Status == "" {
		_ = os.Remove(filepath.Join(n.cfg.StateDir, enrollmentFile))
		return
	}
	b, _ := json.Marshal(e)
	path := filepath.Join(n.cfg.StateDir, enrollmentFile)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		n.log.Warn("enrollment state not saved", "err", err)
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		n.log.Warn("enrollment state not saved", "err", err)
	}
}
