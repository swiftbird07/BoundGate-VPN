package api

import "net/http"

// AdminDeniedForTest lets the control package's tests see the mark that
// adminGate sets.
func AdminDeniedForTest(r *http.Request) bool { return adminDenied(r) }
