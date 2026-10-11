//go:build linux

package vmlab

import (
	"errors"
	"strings"
)

// pacman -Q is the version oracle; pacman -Qi supplies architecture through
// libalpm's native human-readable query, independently of the agent desc parser.
// Installed-package truth reads only the local database, so the query uses a
// repository-free configuration: a freshly installed system without sync
// databases (Omarchy's offline ISO install) otherwise warns on stderr for
// every configured repository.
const pacmanTruthCommand = `env -i PATH=/usr/bin:/bin HOME=/ LANG=C LC_ALL=C /bin/sh -eu -c '/usr/bin/pacman --config /dev/null -Q; printf "\n--LINDM-ARCH-DETAILS--\n"; /usr/bin/pacman --config /dev/null -Qi'`

func parsePacmanTruth(data []byte) (map[nativePackage]int, error) {
	list, detail, found := strings.Cut(string(data), "\n--LINDM-ARCH-DETAILS--\n")
	if !found || !strings.HasSuffix(list, "\n") || !strings.HasSuffix(detail, "\n\n") {
		return nil, errors.New("truncated pacman oracle")
	}
	versions := make(map[string]string)
	for _, line := range strings.Split(strings.TrimSuffix(list, "\n"), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || versions[fields[0]] != "" || len(versions) >= 100000 {
			return nil, errors.New("invalid pacman -Q oracle")
		}
		versions[fields[0]] = fields[1]
	}
	result := make(map[nativePackage]int, len(versions))
	name, version, arch := "", "", ""
	flush := func() error {
		if name == "" || version == "" || arch == "" || versions[name] != version {
			return errors.New("pacman query identity disagreement")
		}
		pkg := nativePackage{name: name, version: version, architecture: arch, manager: "pacman", module: nativeModule{status: truthUnavailable}}
		if result[pkg] != 0 {
			return errors.New("duplicate pacman detail")
		}
		result[pkg] = 1
		name, version, arch = "", "", ""
		return nil
	}
	for _, line := range strings.Split(detail, "\n") {
		if line == "" {
			if name != "" {
				if err := flush(); err != nil {
					return nil, err
				}
			}
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch strings.TrimSpace(key) {
		case "Name":
			if name != "" {
				return nil, errors.New("duplicate pacman name")
			}
			name = strings.TrimSpace(value)
		case "Version":
			if version != "" {
				return nil, errors.New("duplicate pacman version")
			}
			version = strings.TrimSpace(value)
		case "Architecture":
			if arch != "" {
				return nil, errors.New("duplicate pacman architecture")
			}
			arch = strings.TrimSpace(value)
		}
	}
	if len(result) == 0 || len(result) != len(versions) {
		return nil, errors.New("incomplete pacman native oracle")
	}
	return result, nil
}
