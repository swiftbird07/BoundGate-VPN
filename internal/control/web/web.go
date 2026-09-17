// Package web serves the admin SPA (Svelte, built into dist/ by `make web`)
// from the control binary. Paths under /api/ never reach it; every other
// path without a file extension gets index.html (client-side routing).
package web

import (
	"embed"
	"io/fs"
	"net/http"
	"path"
	"strings"
)

//go:embed all:dist
var dist embed.FS

// Handler serves the built SPA. Without a build it answers 503 so the API
// keeps working.
func Handler() http.Handler {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		panic(err)
	}
	files := http.FS(sub)
	_, statErr := fs.Stat(sub, "index.html")
	built := statErr == nil
	server := http.FileServer(files)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !built {
			http.Error(w, "admin UI not built into this binary (run make web)", http.StatusServiceUnavailable)
			return
		}
		p := path.Clean("/" + r.URL.Path)
		if p != "/" {
			if f, err := sub.Open(strings.TrimPrefix(p, "/")); err == nil {
				f.Close()
				if strings.HasPrefix(p, "/assets/") {
					w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
				}
				server.ServeHTTP(w, r)
				return
			}
			if strings.Contains(path.Base(p), ".") {
				http.NotFound(w, r)
				return
			}
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "same-origin")
		r2 := r.Clone(r.Context())
		r2.URL.Path = "/"
		server.ServeHTTP(w, r2)
	})
}
