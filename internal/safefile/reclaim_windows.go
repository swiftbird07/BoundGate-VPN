package safefile

// Windows: the service's directories are protected by their DACL, and there
// is no unprivileged worker that could put something under the service's
// names. Nothing is removed.
func Reclaim(path string) (bool, error) { return false, nil }
