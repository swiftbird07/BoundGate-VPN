// Package listsource keeps ACL lists in step with a file somewhere else: a
// list may carry a URL, and the control plane fetches it every interval and
// replaces the list's entries with what it finds. The point is lists that
// live in a Git repository next to the rest of an organisation's
// configuration (a raw file URL of GitHub, GitLab or Gitea), or a feed of
// addresses someone else maintains.
//
// What a source may contain is exactly what an admin may type into a list
// (docs/ACL.md): one entry per line with # comments, or a JSON array of
// strings. Entries are checked and normalized like every other entry, and a
// file the control plane cannot read leaves the list as it was, with the
// reason in the list's status.
package listsource

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/control/db"
)

const (
	// MaxBytes bounds what a source may send; the entry limit
	// (db.MaxListEntries) bounds what of it becomes a list.
	MaxBytes = 4 << 20
	timeout  = 30 * time.Second
)

// Notifier is the snapshot source: a list that changed reaches the nodes.
type Notifier interface{ Notify(version uint64) }

// Fetcher fetches one list's source.
type Fetcher struct {
	Client *http.Client
	Log    *slog.Logger
}

// New returns a Fetcher with a client that follows no redirect to another
// host silently: a source is the URL an admin entered.
func New(log *slog.Logger) *Fetcher {
	return &Fetcher{Log: log, Client: &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("too many redirects")
			}
			if req.URL.Host != via[0].URL.Host {
				return fmt.Errorf("redirect to another host (%s)", req.URL.Host)
			}
			return nil
		},
	}}
}

// Fetch reads l's source and stores the outcome. It returns the list as it
// is afterwards, the snapshot version when the entries changed (0
// otherwise), and the error the admin should see. The list keeps its
// entries when anything goes wrong.
func (f *Fetcher) Fetch(ctx context.Context, store *db.DB, src Notifier, l db.List) (db.List, uint64, error) {
	if l.SourceURL == "" {
		return l, 0, errors.New("this list has no source")
	}
	entries, etag, err := f.get(ctx, l)
	status := ""
	if err != nil {
		status = err.Error()
	}
	version, saveErr := store.SaveListFetch(ctx, l.ID, entries, etag, status)
	if saveErr != nil {
		return l, 0, saveErr
	}
	if version > 0 && src != nil {
		src.Notify(version)
	}
	if f.Log != nil {
		switch {
		case err != nil:
			f.Log.Warn("list source", "list", l.Name, "url", l.SourceURL, "err", err)
		case version > 0:
			f.Log.Info("list source: entries replaced", "list", l.Name, "url", l.SourceURL, "entries", len(entries), "snapshot_version", version)
		}
	}
	out, dbErr := store.ListByID(ctx, l.ID)
	if dbErr != nil {
		return l, version, err
	}
	return out, version, err
}

// get returns the entries a source holds, or nil when they are unchanged
// (304) or the fetch failed.
func (f *Fetcher) get(ctx context.Context, l db.List) ([]string, string, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, l.SourceURL, nil)
	if err != nil {
		return nil, "", fmt.Errorf("source url: %w", err)
	}
	req.Header.Set("Accept", "text/plain, application/json;q=0.9, */*;q=0.1")
	req.Header.Set("User-Agent", "BoundGate")
	if l.SourceETag != "" {
		req.Header.Set("If-None-Match", l.SourceETag)
	}
	if l.SourceHeader != "" && l.SourceSecret != "" {
		req.Header.Set(l.SourceHeader, l.SourceSecret)
	}
	rsp, err := f.Client.Do(req)
	if err != nil {
		// the URL is in the list already; the error must not repeat the
		// token a private repository's header carries
		return nil, "", errors.New(cleanErr(err, l))
	}
	defer rsp.Body.Close()
	switch {
	case rsp.StatusCode == http.StatusNotModified:
		return nil, "", nil
	case rsp.StatusCode != http.StatusOK:
		return nil, "", fmt.Errorf("the source answered HTTP %d", rsp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(rsp.Body, MaxBytes+1))
	if err != nil {
		return nil, "", fmt.Errorf("reading the source: %w", err)
	}
	if len(body) > MaxBytes {
		return nil, "", fmt.Errorf("the source is larger than %d bytes", MaxBytes)
	}
	entries, err := Parse(l.Kind, body)
	if err != nil {
		return nil, "", err
	}
	return entries, rsp.Header.Get("ETag"), nil
}

// Parse turns the bytes of a source or an import into entries of a kind: a
// JSON array of strings, or one entry per line with # comments.
func Parse(kind string, body []byte) ([]string, error) {
	text := strings.TrimSpace(string(body))
	var lines []string
	if strings.HasPrefix(text, "[") {
		if err := json.Unmarshal([]byte(text), &lines); err != nil {
			return nil, fmt.Errorf("the source looks like JSON but is not an array of strings: %w", err)
		}
	} else {
		lines = strings.Split(text, "\n")
	}
	entries, err := db.CleanListEntries(kind, lines)
	if err != nil {
		return nil, fmt.Errorf("the source does not fit a list of kind %s: %w", kind, err)
	}
	return entries, nil
}

// cleanErr keeps a secret out of an error a transport built from the
// request (it may quote headers or the URL).
func cleanErr(err error, l db.List) string {
	s := err.Error()
	if l.SourceSecret != "" {
		s = strings.ReplaceAll(s, l.SourceSecret, "…")
	}
	return s
}

// Run fetches every list whose source is due, for as long as ctx lives. It
// is the control plane's background loop.
func Run(ctx context.Context, store *db.DB, src Notifier, log *slog.Logger) {
	f := New(log)
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		due, err := store.ListsDue(ctx)
		if err != nil && ctx.Err() == nil {
			log.Error("list sources", "err", err)
		}
		for _, l := range due {
			if ctx.Err() != nil {
				return
			}
			_, _, _ = f.Fetch(ctx, store, src, l) // the reason is in the list's status
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
