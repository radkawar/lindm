// SPDX-License-Identifier: Apache-2.0

//go:build linux

// Package rhsm resolves registry-approved repositories from root-owned device
// RHSM state. It never registers devices, transports credentials or trusts host
// repository defaults; only pinned CDN TLS and the vendor release key are used.
package rhsm

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"errors"
	"net/url"
	"path/filepath"
	"slices"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"

	"lindm/internal/platform"
)

// ErrRegistrationRequired is intentionally free of local credentials/endpoints.
var ErrRegistrationRequired = errors.New("rhsm_registration_required")

// ReleaseKey extracts only the pinned public release key. Vendor key files may
// contain separately armored auxiliary or unsupported post-quantum keys; these
// are never imported into the isolated RPM verification database.
func ReleaseKey(raw []byte, fingerprint string) ([]byte, []byte, error) {
	var selected *openpgp.Entity
	remaining := raw
	for len(remaining) != 0 {
		start := bytes.Index(remaining, []byte("-----BEGIN PGP PUBLIC KEY BLOCK-----"))
		if start < 0 {
			break
		}
		remaining = remaining[start:]
		end := bytes.Index(remaining, []byte("-----END PGP PUBLIC KEY BLOCK-----"))
		if end < 0 {
			return nil, nil, errors.New("rhsm: malformed vendor public key")
		}
		end += len("-----END PGP PUBLIC KEY BLOCK-----")
		entities, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(remaining[:end]))
		remaining = remaining[end:]
		if err != nil {
			continue // Unsupported additional keys are not trusted or imported.
		}
		for _, entity := range entities {
			if !strings.EqualFold(hex.EncodeToString(entity.PrimaryKey.Fingerprint), fingerprint) {
				continue
			}
			if selected != nil || entity.PrivateKey != nil || len(entity.Revocations) != 0 {
				return nil, nil, errors.New("rhsm: ambiguous or revoked vendor release key")
			}
			selected = entity
		}
	}
	if selected == nil {
		return nil, nil, errors.New("rhsm: pinned vendor release key unavailable")
	}
	// rpm --import accepts a public ASCII-armored export, not raw OpenPGP
	// packets. Armor only the selected entity, never the surrounding keyring.
	var public bytes.Buffer
	armored, err := armor.Encode(&public, openpgp.PublicKeyType, nil)
	if err != nil {
		return nil, nil, errors.New("rhsm: encode vendor release key")
	}
	if err := errors.Join(selected.Serialize(armored), armored.Close()); err != nil {
		return nil, nil, errors.New("rhsm: invalid vendor release key")
	}
	return public.Bytes(), selected.PrimaryKey.Fingerprint, nil
}

// RepositoryConfig reads only root-custodied RHSM files and emits only the exact
// approved architecture's BaseOS/AppStream definitions. Credential contents and
// native diagnostics never leave the device or appear in an error.
func RepositoryConfig(vendor platform.VendorRepository, architecture, keyFile string, read func(string) ([]byte, error)) (string, error) {
	entitled := vendor.Entitled
	if entitled == nil || read == nil || len(entitled.NativeIDs[architecture]) == 0 {
		return "", ErrRegistrationRequired
	}
	raw, err := read(entitled.File)
	if err != nil || len(raw) > 1<<20 {
		return "", ErrRegistrationRequired
	}
	sections, err := parse(raw, entitled.NativeIDs[architecture])
	if err != nil {
		return "", ErrRegistrationRequired
	}
	var config strings.Builder
	var validatedPaths [3]string
	for _, id := range entitled.NativeIDs[architecture] {
		fields := sections[id]
		fields["baseurl"] = strings.ReplaceAll(strings.ReplaceAll(fields["baseurl"], "$releasever", entitled.ReleaseVersion), "$basearch", architecture)
		if !validFields(fields, vendor) {
			return "", ErrRegistrationRequired
		}
		for i, path := range []string{fields["sslcacert"], fields["sslclientcert"], fields["sslclientkey"]} {
			if validatedPaths[i] == path {
				continue
			}
			contents, err := read(path)
			if err != nil || len(contents) == 0 {
				return "", ErrRegistrationRequired
			}
			validatedPaths[i] = path
		}
		config.WriteString("[" + id + "]\nname=Lindm approved entitled repository\n")
		for _, name := range []string{"baseurl", "sslcacert", "sslclientcert", "sslclientkey"} {
			config.WriteString(name + "=" + fields[name] + "\n")
		}
		config.WriteString("enabled=1\ngpgcheck=1\nrepo_gpgcheck=0\nsslverify=1\nskip_if_unavailable=0\ngpgkey=file://" + keyFile + "\n")
		if fields["sslverifystatus"] == "1" {
			config.WriteString("sslverifystatus=1\n")
		}
		config.WriteString("\n")
	}
	return config.String(), nil
}

func parse(raw []byte, allowed []string) (map[string]map[string]string, error) {
	sections := make(map[string]map[string]string)
	seen := make(map[string]bool)
	var current map[string]string
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 4096), 16<<10)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			if !strings.HasSuffix(line, "]") || strings.Count(line, "[") != 1 || strings.Count(line, "]") != 1 {
				return nil, ErrRegistrationRequired
			}
			id := line[1 : len(line)-1]
			if seen[id] || len(seen) >= 4096 {
				return nil, ErrRegistrationRequired
			}
			seen[id] = true
			current = nil
			if slices.Contains(allowed, id) {
				current = make(map[string]string)
				sections[id] = current
			}
			continue
		}
		if current == nil {
			continue
		}
		name, value, ok := strings.Cut(line, "=")
		name, value = strings.ToLower(strings.TrimSpace(name)), strings.TrimSpace(value)
		if !ok || name == "" || value == "" || strings.ContainsAny(value, "\r\n\x00") {
			return nil, ErrRegistrationRequired
		}
		if _, duplicate := current[name]; duplicate {
			return nil, ErrRegistrationRequired
		}
		current[name] = value
	}
	if err := scanner.Err(); err != nil || len(sections) != len(allowed) {
		return nil, ErrRegistrationRequired
	}
	return sections, nil
}

func validFields(fields map[string]string, vendor platform.VendorRepository) bool {
	e := vendor.Entitled
	if fields["enabled"] != "1" || fields["gpgcheck"] != "1" || fields["sslverify"] != "1" || fields["gpgkey"] != "file://"+vendor.KeyFile || fields["sslcacert"] != e.CAFile {
		return false
	}
	// Drop descriptive/tuning fields, never inherit authentication overrides,
	// proxies, mirrorlists or trust-disabling options from the host config.
	for name := range fields {
		switch name {
		case "name", "enabled", "gpgcheck", "sslverify", "gpgkey", "sslcacert", "sslclientcert", "sslclientkey", "baseurl", "metadata_expire", "enabled_metadata", "ui_repoid_vars", "cost", "priority":
		case "repo_gpgcheck":
			if fields[name] != "0" {
				return false
			}
		case "sslverifystatus":
			if fields[name] != "1" {
				return false
			}
		case "skip_if_unavailable":
			if fields[name] != "0" && !strings.EqualFold(fields[name], "false") {
				return false
			}
		default:
			return false
		}
	}
	u, err := url.Parse(fields["baseurl"])
	if err != nil || u.Scheme != "https" || u.Host != e.Host || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.RawPath != "" || !strings.HasPrefix(u.Path, "/content/") || strings.ContainsAny(u.Path, " \t\\") {
		return false
	}
	pathWithoutVariables := strings.NewReplacer("$releasever", "", "$basearch", "").Replace(u.Path)
	if strings.ContainsAny(pathWithoutVariables, "${}") {
		return false
	}
	for _, component := range strings.Split(u.Path, "/") {
		if component == "." || component == ".." {
			return false
		}
	}
	cert, key := fields["sslclientcert"], fields["sslclientkey"]
	if !safeCredential(cert, e.CertificateDirectory) || !safeCredential(key, e.CertificateDirectory) || strings.HasSuffix(cert, "-key.pem") || key != strings.TrimSuffix(cert, ".pem")+"-key.pem" {
		return false
	}
	return true
}

func safeCredential(path, directory string) bool {
	if filepath.Dir(path) != directory || filepath.Clean(path) != path || strings.ContainsAny(path, " \t\r\n\"[];$") || !strings.HasSuffix(path, ".pem") {
		return false
	}
	return path != ""
}
