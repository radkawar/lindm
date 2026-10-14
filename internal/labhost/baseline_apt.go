// SPDX-License-Identifier: Apache-2.0

package labhost

import (
	"bufio"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
)

const baselineAPTSourcePath = "/etc/apt/sources.list.d/ubuntu.sources"

// Every APT operation uses only the reviewed Ubuntu source file. Disabling the
// binary caches prevents a cache built from unrelated sourceparts from widening
// resolution. Disable list cleanup so scoped updates preserve other repositories'
// cached indexes. APT selects the indexes used for resolution by source.
// Explicit authentication settings never relax repository signature failures.
const baselineAPTOptions = " -o Dir::Etc::sourcelist=" + baselineAPTSourcePath +
	" -o Dir::Etc::sourceparts=- -o Dir::Cache::pkgcache= -o Dir::Cache::srcpkgcache=" +
	" -o APT::Get::List-Cleanup=false" +
	" -o APT::Get::AllowUnauthenticated=false -o Acquire::AllowInsecureRepositories=false" +
	" -o Acquire::AllowDowngradeToInsecureRepositories=false -o Acquire::AllowWeakRepositories=false" +
	" -o Acquire::Check-Date=true -o Acquire::Check-Valid-Until=true"

// validateBaselineSources accepts the distribution's deb822 Ubuntu source
// configuration, not third-party keys or trust overrides. No source/key file is
// repaired or rewritten. A host with a different layout gets an actionable error.
func validateBaselineSources(data, architecture string) error {
	seenSuites := make(map[string]bool)
	fields := make(map[string]string)
	last := ""
	validateStanza := func() error {
		if len(fields) == 0 {
			return nil
		}
		for key := range fields {
			switch key {
			case "types", "uris", "suites", "components", "signed-by", "architectures", "enabled":
			default:
				return fmt.Errorf("unsupported Ubuntu source field %q; trust overrides are not permitted", key)
			}
		}
		if fields["enabled"] != "" && fields["enabled"] != "yes" {
			return errors.New("labhost: Ubuntu baseline source entries must be enabled")
		}
		if fields["signed-by"] != "/usr/share/keyrings/ubuntu-archive-keyring.gpg" {
			return errors.New("labhost: Ubuntu source must use the distribution ubuntu-archive-keyring.gpg with Signed-By")
		}
		types := strings.Fields(fields["types"])
		if !slices.Contains(types, "deb") {
			return errors.New("labhost: Ubuntu source must include binary deb packages")
		}
		for _, kind := range types {
			if kind != "deb" && kind != "deb-src" {
				return fmt.Errorf("labhost: unsupported Ubuntu source type %q", kind)
			}
		}
		if archs := strings.Fields(fields["architectures"]); len(archs) != 0 && !slices.Contains(archs, architecture) {
			return fmt.Errorf("labhost: Ubuntu source excludes native architecture %s", architecture)
		}
		uris := strings.Fields(fields["uris"])
		if len(uris) == 0 {
			return errors.New("labhost: Ubuntu source has no URI")
		}
		for _, raw := range uris {
			u, err := url.Parse(raw)
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Port() != "" {
				return fmt.Errorf("labhost: unsupported official Ubuntu source URI %q", raw)
			}
			if !officialUbuntuSource(u.Hostname(), strings.TrimSuffix(u.Path, "/")) {
				return fmt.Errorf("labhost: baseline refuses nonofficial Ubuntu source URI %q", raw)
			}
		}
		components := strings.Fields(fields["components"])
		if !slices.Contains(components, "main") || !slices.Contains(components, "universe") {
			return errors.New("labhost: Ubuntu baseline sources require main and universe components")
		}
		suites := strings.Fields(fields["suites"])
		if len(suites) == 0 {
			return errors.New("labhost: Ubuntu source has no suite")
		}
		for _, suite := range suites {
			if !slices.Contains([]string{"noble", "noble-updates", "noble-security", "noble-backports"}, suite) {
				return fmt.Errorf("labhost: unsupported Ubuntu baseline suite %q", suite)
			}
			seenSuites[suite] = true
		}
		return nil
	}
	scanner := bufio.NewScanner(strings.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		if strings.TrimSpace(line) == "" {
			if err := validateStanza(); err != nil {
				return err
			}
			clear(fields)
			last = ""
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			if last == "" {
				return errors.New("labhost: Ubuntu source continuation has no field")
			}
			fields[last] += " " + strings.TrimSpace(line)
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		key = strings.ToLower(key)
		if _, duplicate := fields[key]; !ok || key == "" || duplicate {
			return errors.New("labhost: Ubuntu source contains a malformed or duplicate field")
		}
		fields[key], last = strings.TrimSpace(value), key
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if err := validateStanza(); err != nil {
		return err
	}
	for _, suite := range []string{"noble", "noble-updates", "noble-security"} {
		if !seenSuites[suite] {
			return fmt.Errorf("labhost: Ubuntu baseline sources are missing suite %s", suite)
		}
	}
	return nil
}

// officialUbuntuSource reports whether host and path name the Ubuntu archive,
// security or ports mirror.
func officialUbuntuSource(host, path string) bool {
	archive := host == "archive.ubuntu.com" || strings.HasSuffix(host, ".archive.ubuntu.com") || host == "security.ubuntu.com"
	return archive && path == "/ubuntu" || host == "ports.ubuntu.com" && path == "/ubuntu-ports"
}
