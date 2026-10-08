// Package buildinfo reports the agent build identity used as packaging evidence.
// Version is the packaging linker stamp:
//
//	-X lindm/internal/agent/buildinfo.Version=<upstream>
//
// lindm-agent version prints that stamp and a newline, nothing else.
// Revision is available to other packaging evidence and is not part of that line.
// Empty stamps are not replaced with a fabricated release identifier.
package buildinfo

import "runtime/debug"

// Version and Revision are set by packaging ldflags. Leave them empty in source.
var (
	Version  string
	Revision string
)

// Info is the identity of this process build.
type Info struct {
	Version   string
	Revision  string
	GoVersion string
	Time      string
	Modified  string
}

// Current prefers an explicit packaging stamp and otherwise uses Go build info.
func Current() Info {
	info := Info{Version: Version, Revision: Revision}
	build, ok := debug.ReadBuildInfo()
	if !ok {
		return info
	}
	info.GoVersion = build.GoVersion
	if info.Version == "" {
		info.Version = build.Main.Version
	}
	for _, setting := range build.Settings {
		switch setting.Key {
		case "vcs.revision":
			if info.Revision == "" {
				info.Revision = setting.Value
			}
		case "vcs.time":
			info.Time = setting.Value
		case "vcs.modified":
			info.Modified = setting.Value
		}
	}
	return info
}

// Line is the exact packaging version proof: the upstream version and a newline.
// An unstamped development build uses the Go module version when one exists.
func Line() string {
	version := Version
	if version == "" {
		if build, ok := debug.ReadBuildInfo(); ok && build.Main.Version != "" {
			version = build.Main.Version
		}
	}
	if version == "" {
		version = "unavailable"
	}
	return version + "\n"
}
