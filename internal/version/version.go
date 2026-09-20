// Package version holds what a build knows about itself. Release builds set
// Version with -ldflags "-X …/internal/version.Version=v1.2.3"; everything
// else is "dev", which no release is compared against.
package version

// Version is the release tag of this build, or "dev".
var Version = "dev"

// Commit is the source revision of this build, if known.
var Commit = ""

// IsRelease reports whether this build came out of the release pipeline.
func IsRelease() bool { return Version != "dev" && Version != "" }
