// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/packaging"
	"lindm/internal/platform"
)

const nativeGuestDir = "/var/tmp/lindm-native-lab"

var nativeVersion = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)
var nativeFingerprint = regexp.MustCompile(`^(?:[A-F0-9]{40}|[A-F0-9]{64})$`)

// nativeGuestPackages operates exclusively through native managers in a
// disposable guest. Caller-owned artifacts are checked against their build
// digests; the guest then authenticates them independently with a pinned key.
// It owns no VM and must be closed before its VM is removed.
type nativeGuestPackages struct {
	vm              *guestVM
	backend         platform.Backend
	first           packaging.Artifact
	second          packaging.Artifact
	apt             *packaging.APTRepository
	arch            []*packaging.ArchRepository
	keyPath         string
	server          *aptPublicServer
	forward         *guestForward
	account         string
	installed       bool
	rollingSnapshot *resourcev1.RollingUpdateSnapshot
	// osUpdateTarget is the registry's later os-update policy snapshot.
	osUpdateTarget *resourcev1.RollingUpdateSnapshot
	// executorConfigMode is the octal mode /etc/lindm/executor.json must keep
	// across install and upgrade: empty is the packaged 640; a lane that
	// installs a local action qualification hardens it to 600, and an upgrade
	// must preserve that.
	executorConfigMode string
}

func nativeQuote(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'" }

func nativeArtifactFile(a packaging.Artifact) (*os.File, error) {
	if !nativeVersion.MatchString(a.Version) || (a.Format != packaging.FormatDEB && a.Format != packaging.FormatRPM && a.Format != packaging.FormatArch) || a.Size <= 0 || a.Size > 1<<30 {
		return nil, errors.New("invalid native build artifact metadata")
	}
	if len(a.SHA256) != 64 {
		return nil, errors.New("invalid native artifact digest")
	}
	if _, err := hex.DecodeString(a.SHA256); err != nil {
		return nil, errors.New("invalid native artifact digest")
	}
	info, err := os.Lstat(a.Path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("native artifact is not a regular file")
	}
	file, err := os.Open(a.Path)
	if err != nil {
		return nil, err
	}
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) || opened.Size() != a.Size {
		_ = file.Close()
		return nil, errors.New("native artifact changed while opening")
	}
	h := sha256.New()
	n, err := io.Copy(h, file)
	if err != nil || n != a.Size || hex.EncodeToString(h.Sum(nil)) != strings.ToLower(a.SHA256) {
		_ = file.Close()
		return nil, errors.New("native artifact differs from build digest")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}

func newNativeGuestPackages(ctx context.Context, vm *guestVM, first, second packaging.Artifact, apt *packaging.APTRepository, publicKeyPath, signerFingerprint string, arch ...*packaging.ArchRepository) (_ *nativeGuestPackages, err error) {
	if first.Format != second.Format || !nativeFingerprint.MatchString(signerFingerprint) {
		return nil, errors.New("native packages require matching formats and a pinned signing fingerprint")
	}
	release, err := vm.run(ctx, "if [ -r /etc/os-release ]; then . /etc/os-release; else . /usr/lib/os-release; fi; printf '%s\\n%s\\n' \"$ID\" \"${VERSION_ID-}\"", nil, 4096, 15*time.Second)
	if err != nil {
		return nil, fmt.Errorf("read native package distribution: %w", err)
	}
	id, versionID, _ := strings.Cut(strings.TrimSpace(string(release)), "\n")
	guest := platform.Identify(platform.OSRelease{ID: id, VersionID: versionID})
	backend, err := nativeBackend(guest)
	if err != nil {
		return nil, err
	}
	format, err := NativePackageFormat(guest)
	if err != nil {
		return nil, err
	}
	if first.Format != format {
		return nil, errors.New("native package format differs from guest distribution")
	}
	for _, artifact := range []packaging.Artifact{first, second} {
		file, err := nativeArtifactFile(artifact)
		if err != nil {
			return nil, err
		}
		if err := file.Close(); err != nil {
			return nil, err
		}
	}
	if first.Format == packaging.FormatDEB && apt == nil {
		return nil, errors.New("DEB lifecycle requires a signed APT repository")
	}
	if first.Format == packaging.FormatDEB {
		info, err := os.Lstat(filepath.Join(apt.Root, "dists", packaging.APTDistribution, "InRelease"))
		if err != nil || !info.Mode().IsRegular() {
			return nil, errors.New("positive APT lifecycle requires InRelease")
		}
	}
	p := &nativeGuestPackages{vm: vm, backend: backend, first: first, second: second, apt: apt, arch: arch}
	defer func() {
		if err != nil {
			err = errors.Join(err, p.Close())
		}
	}()
	key, err := os.Open(publicKeyPath)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, key.Close()) }()
	info, err := key.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 1<<20 {
		return nil, errors.New("invalid pinned public key file")
	}
	keyBytes, err := io.ReadAll(io.LimitReader(key, (1<<20)+1))
	if err != nil || len(keyBytes) > 1<<20 {
		return nil, errors.New("read pinned public key")
	}
	// gpg is run only against a private lab home and an already opened public
	// file. No host keyring, package database, or trust store is modified.
	home, err := os.MkdirTemp(vm.dir, "package-public-key-")
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, os.RemoveAll(home)) }()
	keySnapshot := filepath.Join(home, "public.key")
	if err := os.WriteFile(keySnapshot, keyBytes, 0600); err != nil {
		return nil, err
	}
	openedKey, err := os.Open(keySnapshot)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, openedKey.Close()) }()
	listed, err := hostCommand(ctx, home, "gpg", []*os.File{openedKey}, "--no-options", "--batch", "--homedir", home, "--with-colons", "--show-keys", "/proc/self/fd/3")
	if err != nil {
		return nil, fmt.Errorf("inspect pinned public package key: %w", err)
	}
	pubs, primary, expecting := 0, "", false
	for _, line := range strings.Split(string(listed), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) < 10 {
			continue
		}
		switch fields[0] {
		case "sec", "ssb":
			return nil, errors.New("package trust input contains secret keys")
		case "pub":
			pubs++
			expecting = true
		case "fpr":
			if expecting {
				primary = fields[9]
				expecting = false
			}
		}
	}
	if pubs != 1 || primary != signerFingerprint {
		return nil, errors.New("public package key does not match pinned fingerprint")
	}
	p.keyPath = nativeGuestDir + "/signer.gpg"
	if bytes.HasPrefix(keyBytes, []byte("-----BEGIN PGP PUBLIC KEY BLOCK-----")) {
		p.keyPath = nativeGuestDir + "/signer.asc"
	}
	if first.Format == packaging.FormatRPM && !strings.HasSuffix(p.keyPath, ".asc") {
		return nil, errors.New("RPM lifecycle requires the ASCII-armored public signing key")
	}
	if err := p.command(ctx, "prepare native guest", "test ! -e "+nativeGuestDir+"; install -d -m 0755 "+nativeGuestDir+" "+nativeGuestDir+"/empty "+nativeGuestDir+"/lists "+nativeGuestDir+"/archives; install -d -m 0700 "+nativeGuestDir+"/rpmkeys", nil); err != nil {
		return nil, err
	}
	if err := p.uploadBytes(ctx, p.keyPath, keyBytes); err != nil {
		return nil, err
	}
	switch first.Format {
	case packaging.FormatRPM:
		if err := p.command(ctx, "import pinned RPM key", "rpmkeys --dbpath "+nativeGuestDir+"/rpmkeys --import "+p.keyPath+"; rpmkeys --import "+p.keyPath, nil); err != nil {
			return nil, err
		}
		if backend == platform.BackendZypper {
			// Local RPM transactions have no repository metadata. Require the
			// package signature itself, including in negative-authentication cases.
			config := "[main]\ngpgcheck = true\nrepo_gpgcheck = true\npkg_gpgcheck = true\n"
			if err := p.uploadBytes(ctx, nativeGuestDir+"/zypp.conf", []byte(config)); err != nil {
				return nil, err
			}
		}
	case packaging.FormatArch:
		if err := p.prepareArch(ctx, signerFingerprint); err != nil {
			return nil, err
		}
	default:
		if err := p.startAPT(ctx, apt, []packaging.Artifact{first, second}); err != nil {
			return nil, err
		}
	}
	return p, nil
}

func (p *nativeGuestPackages) result(ctx context.Context, command string, input io.Reader) (guestCommandResult, error) {
	return p.vm.runResult(ctx, "sudo -n env LC_ALL=C DEBIAN_FRONTEND=noninteractive sh -eu -c "+nativeQuote(command), input, 4<<20, 5*time.Minute)
}

func (p *nativeGuestPackages) command(ctx context.Context, step, command string, input io.Reader) error {
	result, err := p.result(ctx, command, input)
	if err != nil {
		return fmt.Errorf("%s: %w", step, err)
	}
	if result.ExitCode != 0 {
		return fmt.Errorf("%s: native guest exit %d (stdout bytes %d, stderr bytes %d)", step, result.ExitCode, len(result.Stdout), len(result.Stderr))
	}
	return nil
}

// aptMetadataCommand runs apt-get update against the lab's public fixture
// repository. Its output names only that repository and APT's own errors, so
// a failure carries it: on Pop!_OS 24.04 the step failed with exit 100 and no
// other evidence (pop2404-assistance-06..08).
func (p *nativeGuestPackages) aptMetadataCommand(ctx context.Context) error {
	result, err := p.result(ctx, p.aptCommand("update"), nil)
	if err != nil {
		return fmt.Errorf("authenticate APT metadata: %w", err)
	}
	if result.ExitCode != 0 {
		return fmt.Errorf("authenticate APT metadata: native guest exit %d (stdout %q, stderr %q)", result.ExitCode, bytes.TrimSpace(result.Stdout), bytes.TrimSpace(result.Stderr))
	}
	return nil
}

func (p *nativeGuestPackages) uploadBytes(ctx context.Context, destination string, data []byte) error {
	hash := sha256.Sum256(data)
	return p.command(ctx, "upload native public input", "umask 022; cat > "+nativeQuote(destination)+"; printf '%s  %s\\n' "+nativeQuote(hex.EncodeToString(hash[:]))+" "+nativeQuote(destination)+" | sha256sum --check --status", bytes.NewReader(data))
}

func (p *nativeGuestPackages) uploadArtifact(ctx context.Context, a packaging.Artifact, destination string) (err error) {
	file, err := nativeArtifactFile(a)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	return p.command(ctx, "upload native package", "umask 022; cat > "+nativeQuote(destination)+"; test \"$(stat -c %s "+nativeQuote(destination)+")\" = "+strconv.FormatInt(a.Size, 10)+"; printf '%s  %s\\n' "+nativeQuote(strings.ToLower(a.SHA256))+" "+nativeQuote(destination)+" | sha256sum --check --status", file)
}

func (p *nativeGuestPackages) stopAPT() error {
	var err error
	if p.forward != nil {
		err = p.forward.Close()
		p.forward = nil
	}
	if p.server != nil {
		err = errors.Join(err, p.server.Close())
		p.server = nil
	}
	return err
}

func (p *nativeGuestPackages) startAPT(ctx context.Context, repo *packaging.APTRepository, artifacts []packaging.Artifact) error {
	if err := p.stopAPT(); err != nil {
		return err
	}
	if repo == nil || repo.Distribution != packaging.APTDistribution || repo.Component != packaging.APTComponent {
		return errors.New("unexpected APT archive coordinates")
	}
	names := []string{}
	for _, name := range []string{"dists/stable/InRelease", "dists/stable/Release", "dists/stable/Release.gpg"} {
		if _, err := os.Lstat(filepath.Join(repo.Root, name)); err == nil {
			names = append(names, name)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	for _, artifact := range artifacts {
		if artifact.Architecture.Debian != "amd64" && artifact.Architecture.Debian != "arm64" {
			return errors.New("invalid APT artifact architecture")
		}
		name := "pool/main/l/lindm-agent/" + filepath.Base(artifact.Path)
		copy := artifact
		copy.Path = filepath.Join(repo.Root, name)
		file, err := nativeArtifactFile(copy)
		if err != nil {
			return fmt.Errorf("APT pool artifact: %w", err)
		}
		if err := file.Close(); err != nil {
			return err
		}
		names = append(names, name, "dists/stable/main/binary-"+artifact.Architecture.Debian+"/Packages")
		compressed := "dists/stable/main/binary-" + artifact.Architecture.Debian + "/Packages.gz"
		if _, err := os.Lstat(filepath.Join(repo.Root, compressed)); err == nil {
			names = append(names, compressed)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	server, err := newAPTPublicServer(repo.Root, names)
	if err != nil {
		return err
	}
	p.server = server
	context.AfterFunc(ctx, func() { _ = server.Close() })
	// Verify the exact descriptors the server will read, not merely the paths
	// used when assembling its allowlist.
	for _, artifact := range artifacts {
		file := server.files["/pool/main/l/lindm-agent/"+filepath.Base(artifact.Path)]
		h := sha256.New()
		n, err := io.Copy(h, io.NewSectionReader(file, 0, artifact.Size+1))
		if err != nil || n != artifact.Size || hex.EncodeToString(h.Sum(nil)) != strings.ToLower(artifact.SHA256) {
			return errors.Join(errors.New("opened APT payload differs from build digest"), p.stopAPT())
		}
	}
	forward, err := newGuestForward(ctx, p.vm, "127.0.0.1:0", server.listener.Addr().String())
	if err != nil {
		return errors.Join(err, p.stopAPT())
	}
	p.forward = forward
	source := "Types: deb\nURIs: http://" + forward.Addr() + "/\nSuites: stable\nComponents: main\nSigned-By: " + p.keyPath + "\n"
	if err := p.uploadBytes(ctx, nativeGuestDir+"/source.sources", []byte(source)); err != nil {
		return err
	}
	if err := p.uploadBytes(ctx, nativeGuestDir+"/apt.conf", []byte(aptIsolationConfig)); err != nil {
		return err
	}
	return p.command(ctx, "reset isolated APT cache", "rm -rf "+nativeGuestDir+"/lists "+nativeGuestDir+"/archives; install -d -m 0755 "+nativeGuestDir+"/lists "+nativeGuestDir+"/archives", nil)
}

// aptIsolationConfig clears the system's APT::Update hooks for the fixture
// update. They refresh system state, not the isolated lists: Pop!_OS 24.04's
// command-not-found Post-Invoke-Success hook raced the vendor updater's own
// cnf-update-db ("attempt to write a readonly database") and failed the step
// under Error-Mode=any (pop2404-assistance-09). apt-get reads -c files after
// apt.conf.d, so #clear removes the hooks configured there.
const aptIsolationConfig = "#clear APT::Update::Pre-Invoke;\n#clear APT::Update::Post-Invoke;\n#clear APT::Update::Post-Invoke-Success;\n"

func (p *nativeGuestPackages) aptCommand(action string) string {
	return "apt-get -q -y -c " + nativeGuestDir + "/apt.conf -o Dir::Etc::sourcelist=" + nativeGuestDir + "/source.sources -o Dir::Etc::sourceparts=" + nativeGuestDir + "/empty -o Dir::Etc::trusted=" + nativeGuestDir + "/empty/trusted.gpg -o Dir::Etc::trustedparts=" + nativeGuestDir + "/empty -o Dir::State::lists=" + nativeGuestDir + "/lists -o Dir::Cache::archives=" + nativeGuestDir + "/archives -o Acquire::Retries=0 -o Acquire::http::Proxy=false -o Acquire::http::Timeout=20 -o Acquire::AllowInsecureRepositories=false -o Acquire::AllowDowngradeToInsecureRepositories=false -o APT::Get::AllowUnauthenticated=false -o APT::Update::Error-Mode=any " + action
}

func (p *nativeGuestPackages) dnfCommand(action string) string {
	// An empty reposdir excludes every configured repository. DNF5 rejects
	// --disablerepo='*' when there are no repositories to match.
	return "dnf -y --setopt=reposdir=" + nativeGuestDir + "/empty --setopt=gpgcheck=1 --setopt=localpkg_gpgcheck=1 --setopt=install_weak_deps=False --setopt=keepcache=False " + action
}

func (p *nativeGuestPackages) zypperCommand(action string) string {
	// Only explicitly uploaded local packages and the installed system participate.
	// No vendor repository or unsigned, synthetic repository is introduced.
	return "env ZYPP_CONF=" + nativeGuestDir + "/zypp.conf zypper --non-interactive --no-remote --reposd-dir " + nativeGuestDir + "/empty " + action
}

func (p *nativeGuestPackages) rpmInstallCommand(destination string, upgrade bool) string {
	if p.backend == platform.BackendZypper {
		// Zypper install accepts a local RPM for both installation and upgrade.
		return p.zypperCommand("install --no-recommends " + nativeQuote(destination))
	}
	action := "install "
	if upgrade {
		action = "upgrade "
	}
	return p.dnfCommand(action + nativeQuote(destination))
}

func (p *nativeGuestPackages) install(ctx context.Context, artifact packaging.Artifact, upgrade bool) error {
	switch artifact.Format {
	case packaging.FormatDEB:
		if err := p.aptMetadataCommand(ctx); err != nil {
			return err
		}
		action := "install --no-install-recommends "
		if upgrade {
			action += "--only-upgrade "
		}
		if err := p.command(ctx, "install authenticated DEB", p.aptCommand(action+nativeQuote(packaging.PackageName+"="+artifact.Version)), nil); err != nil {
			return err
		}
	case packaging.FormatArch:
		if err := p.installArch(ctx, artifact); err != nil {
			return err
		}
	default:
		destination := nativeGuestDir + "/install.rpm"
		if err := p.uploadArtifact(ctx, artifact, destination); err != nil {
			return err
		}
		signature, err := p.result(ctx, "rpmkeys --dbpath "+nativeGuestDir+"/rpmkeys --verbose --checksig "+destination, nil)
		if err != nil {
			return err
		}
		signed := false
		for _, line := range strings.Split(strings.ToLower(string(signature.Stdout)), "\n") {
			if strings.Contains(line, "signature") && strings.HasSuffix(strings.TrimSpace(line), ": ok") {
				signed = true
			}
		}
		if signature.ExitCode != 0 || !signed {
			return errors.New("RPM did not authenticate against the pinned package key")
		}
		if err := p.command(ctx, "install authenticated RPM", p.rpmInstallCommand(destination, upgrade), nil); err != nil {
			return err
		}
	}
	p.installed = true
	if err := p.assertVersion(ctx, artifact); err != nil {
		return err
	}
	if err := p.assertOwnership(ctx, true); err != nil {
		return err
	}
	return p.AssertServices(ctx, true)
}

func (p *nativeGuestPackages) InstallFirst(ctx context.Context) error {
	return p.install(ctx, p.first, false)
}
func (p *nativeGuestPackages) Upgrade(ctx context.Context) error {
	return p.install(ctx, p.second, true)
}
func (p *nativeGuestPackages) ReinstallSecond(ctx context.Context) error {
	return p.install(ctx, p.second, false)
}

func (p *nativeGuestPackages) assertVersion(ctx context.Context, artifact packaging.Artifact) error {
	var query, expected string
	switch artifact.Format {
	case packaging.FormatDEB:
		query = "dpkg-query -W -f='${db:Status-Status}\\t${Version}\\t${Architecture}\\n' lindm-agent"
		expected = "installed\t" + artifact.Version + "\t" + artifact.Architecture.Debian
	case packaging.FormatArch:
		query = "pacman -Qi lindm-agent | /bin/grep -Eq '^Architecture[[:space:]]*:[[:space:]]*" + artifact.Architecture.Arch + "$'; pacman -Q lindm-agent"
		expected = "lindm-agent " + artifact.Version + "-1"
	default:
		query = "rpm -q --qf '%{VERSION}-%{RELEASE}\\t%{ARCH}\\n' lindm-agent"
		expected = artifact.Version + "-" + packaging.RPMRelease + "\t" + artifact.Architecture.RPM
	}
	result, err := p.result(ctx, query, nil)
	if err != nil {
		return err
	}
	if result.ExitCode != 0 || strings.TrimSpace(string(result.Stdout)) != expected {
		return errors.New("native installed package version/architecture mismatch")
	}
	result, err = p.result(ctx, packaging.BinaryPath+" version", nil)
	if err != nil {
		return err
	}
	if result.ExitCode != 0 || strings.TrimSpace(string(result.Stdout)) != artifact.Version {
		return errors.New("installed agent binary stamp mismatch")
	}
	if len(artifact.PayloadSHA256) != 64 {
		return errors.New("missing built binary digest")
	}
	if _, err := hex.DecodeString(artifact.PayloadSHA256); err != nil {
		return errors.New("invalid built binary digest")
	}
	if err := p.command(ctx, "assert installed binary digest", "printf '%s  %s\\n' "+nativeQuote(strings.ToLower(artifact.PayloadSHA256))+" "+nativeQuote(packaging.BinaryPath)+" | sha256sum --check --status", nil); err != nil {
		return err
	}
	return nil
}

const nativeOwnership = `
uid=$(id -u lindm); gid=$(id -g lindm)
test "$uid" -gt 0; test "$gid" -gt 0
check() {
 test ! -L "$1"
 test "$(stat -c '%u:%g:%a' -- "$1")" = "$2"
}
test -d /var/lib/lindm; check /var/lib/lindm 0:0:755
test -d /var/lib/lindm/executor; check /var/lib/lindm/executor 0:0:700
test -d /var/lib/lindm/agent; check /var/lib/lindm/agent "$uid:$gid:700"
printf '%s:%s\n' "$uid" "$gid"
`

func (p *nativeGuestPackages) assertOwnership(ctx context.Context, installed bool) error {
	command := nativeOwnership
	if installed {
		mode := p.executorConfigMode
		if mode == "" {
			mode = "640"
		}
		command += `
test -f /etc/lindm/executor.json; check /etc/lindm/executor.json 0:0:` + mode + `
test -f /etc/lindm/agent.json; check /etc/lindm/agent.json 0:0:644
test -x ` + packaging.BinaryPath + `; check ` + packaging.BinaryPath + ` 0:0:755
`
	}
	result, err := p.result(ctx, command, nil)
	if err != nil {
		return err
	}
	if result.ExitCode != 0 {
		return errors.New("native account/directory/config ownership assertion failed")
	}
	account := strings.TrimSpace(string(result.Stdout))
	if p.account != "" && p.account != account {
		return errors.New("native lifecycle changed retained account identity")
	}
	p.account = account
	return nil
}

func (p *nativeGuestPackages) AssertServices(ctx context.Context, active bool) error {
	command := `
for unit in lindm-executor.service lindm-agent.service; do
 state=$(systemctl show --property=ActiveState --value "$unit" 2>/dev/null) || test "$state" = inactive
 pid=$(systemctl show --property=MainPID --value "$unit" 2>/dev/null) || test "$pid" = 0
 test "$state" = inactive
 test "$pid" = 0
done
`
	if active {
		command = nativeOwnership + `
for unit in lindm-executor.service lindm-agent.service; do
 test "$(systemctl show --property=ActiveState --value "$unit")" = active
 test "$(systemctl show --property=SubState --value "$unit")" = running
 systemctl is-enabled --quiet "$unit"
 pid=$(systemctl show --property=MainPID --value "$unit")
 test "$pid" -gt 1
 test "$(readlink /proc/"$pid"/exe)" = ` + packaging.BinaryPath + `
 actual=$(stat -c %u /proc/"$pid")
 if [ "$unit" = lindm-executor.service ]; then test "$actual" = 0; else test "$actual" = "$uid"; fi
done
test -d /run/lindm; check /run/lindm "0:$gid:750"
test -S /run/lindm/executor.sock; check /run/lindm/executor.sock "0:$gid:660"
`
		if p.backend.DNF() {
			command += `
test "$(getenforce)" = Enforcing
matchpathcon -V ` + packaging.BinaryPath + `
for unit in lindm-executor.service lindm-agent.service; do
 pid=$(systemctl show --property=MainPID --value "$unit")
 label=$(cat /proc/"$pid"/attr/current)
 test -n "$label"
 case "$label" in
  *:init_t:*) exit 1 ;;
 esac
done
`
		}
	}
	deadline, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	for {
		result, err := p.result(deadline, command, nil)
		if err != nil {
			return fmt.Errorf("assert native service state: %w", err)
		}
		if result.ExitCode == 0 {
			return nil
		}
		select {
		case <-deadline.Done():
			return errors.New("native units did not reach required live state/identity before deadline")
		case <-time.After(time.Second):
		}
	}
}

func (p *nativeGuestPackages) Remove(ctx context.Context, purge bool) error {
	if err := p.assertOwnership(ctx, false); err != nil {
		return err
	}
	before, err := p.result(ctx, "stat -c '%d:%i' /var/lib/lindm/executor /var/lib/lindm/agent", nil)
	if err != nil {
		return err
	}
	if before.ExitCode != 0 {
		return errors.New("cannot snapshot retained state directories")
	}
	switch p.first.Format {
	case packaging.FormatDEB:
		action := "remove lindm-agent"
		if purge {
			action = "purge lindm-agent"
		}
		if err := p.command(ctx, "remove native DEB", p.aptCommand(action), nil); err != nil {
			return err
		}
	case packaging.FormatArch:
		if p.installed {
			if err := p.command(ctx, "remove native Arch package", p.pacmanCommand("-R lindm-agent"), nil); err != nil {
				return err
			}
		}
	default: // RPM has no distinct purge operation. Its erase must retain account and
		// protected state in both requested lifecycle lanes.
		if p.installed {
			command := p.dnfCommand("remove lindm-agent")
			if p.backend == platform.BackendZypper {
				command = p.zypperCommand("remove lindm-agent")
			}
			if err := p.command(ctx, "erase native RPM", command, nil); err != nil {
				return err
			}
		}
	}
	p.installed = false
	absent := "test ! -e " + packaging.BinaryPath + "; "
	switch p.first.Format {
	case packaging.FormatDEB:
		absent += "status=$(dpkg-query -W -f='${db:Status-Status}' lindm-agent 2>/dev/null) || status=missing; test \"$status\" != installed"
		if purge {
			absent += "; test ! -e /etc/lindm/executor.json; test ! -e /etc/lindm/agent.json"
		} else {
			absent += "; test -f /etc/lindm/executor.json; test -f /etc/lindm/agent.json"
		}
	case packaging.FormatArch:
		absent += "if pacman -Q lindm-agent >/dev/null 2>&1; then exit 1; fi"
	default:
		absent += "if rpm -q lindm-agent >/dev/null 2>&1; then exit 1; fi"
	}
	if err := p.command(ctx, "assert native package removal", absent, nil); err != nil {
		return err
	}
	if err := p.AssertServices(ctx, false); err != nil {
		return err
	}
	if err := p.assertOwnership(ctx, false); err != nil {
		return err
	}
	after, err := p.result(ctx, "stat -c '%d:%i' /var/lib/lindm/executor /var/lib/lindm/agent", nil)
	if err != nil {
		return err
	}
	if after.ExitCode != 0 || !bytes.Equal(before.Stdout, after.Stdout) {
		return errors.New("native removal replaced protected state directories")
	}
	return nil
}

// nativeAuthRejection is returned only after a real manager reports a known
// authentication failure and the independent clean-guest checks still pass.
type nativeAuthRejection struct{ Format packaging.Format }

func (e *nativeAuthRejection) Error() string {
	return "native " + string(e.Format) + " authentication rejected package before installation"
}

func (p *nativeGuestPackages) assertPristine(ctx context.Context) error {
	command := `
if getent passwd lindm >/dev/null; then exit 1; fi
for target in ` + packaging.BinaryPath + ` /usr/libexec/lindm/lifecycle /etc/lindm /var/lib/lindm /run/lindm /usr/lib/systemd/system/lindm-agent.service /usr/lib/systemd/system/lindm-executor.service; do
 test ! -e "$target"; test ! -L "$target"
done
`
	switch p.first.Format {
	case packaging.FormatDEB:
		command += "if dpkg-query -W -f='${db:Status-Status}' lindm-agent 2>/dev/null | /bin/grep -qx installed; then exit 1; fi\n"
	case packaging.FormatArch:
		command += "if pacman -Q lindm-agent >/dev/null 2>&1; then exit 1; fi\n"
	default:
		command += "if rpm -q lindm-agent >/dev/null 2>&1; then exit 1; fi\n"
	}
	return p.command(ctx, "assert no rejected-package maintainer effects", command, nil)
}

// RejectArtifact returns *nativeAuthRejection on the EXPECTED failure, not nil.
// Transport failures, unavailable dependencies and unknown native errors remain
// failures of the scenario. Call before InstallFirst, with honest variant hashes.
func (p *nativeGuestPackages) RejectArtifact(ctx context.Context, artifact packaging.Artifact, apt *packaging.APTRepository) (err error) {
	if p.installed || artifact.Format != p.first.Format {
		return errors.New("negative package case requires a clean matching-format guest")
	}
	file, err := nativeArtifactFile(artifact)
	if err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := p.assertPristine(ctx); err != nil {
		return err
	}
	var result guestCommandResult
	switch artifact.Format {
	case packaging.FormatDEB:
		defer func() {
			if restore := p.startAPT(ctx, p.apt, []packaging.Artifact{p.first, p.second}); restore != nil {
				err = errors.Join(errors.New("restore signed APT source after rejection"), restore)
			}
		}()
		if err := p.startAPT(ctx, apt, []packaging.Artifact{artifact}); err != nil {
			return err
		}
		result, err = p.result(ctx, p.aptCommand("update")+"; "+p.aptCommand("install --no-install-recommends "+nativeQuote(packaging.PackageName+"="+artifact.Version)), nil)
	case packaging.FormatArch:
		result, err = p.rejectArch(ctx, artifact)
	default:
		destination := nativeGuestDir + "/rejected.rpm"
		if err := p.uploadArtifact(ctx, artifact, destination); err != nil {
			return err
		}
		result, err = p.result(ctx, p.rpmInstallCommand(destination, false), nil)
	}
	if err != nil {
		return err
	}
	if result.ExitCode == 0 {
		return errors.New("native manager accepted negative authentication artifact")
	}
	expectedExit := 100
	if artifact.Format == packaging.FormatArch {
		expectedExit = 1
	}
	if artifact.Format == packaging.FormatRPM {
		expectedExit = 1
		if p.backend == platform.BackendZypper {
			expectedExit = 8 // ZYPPER_EXIT_ERR_COMMIT: package authentication failed.
		}
	}
	if result.ExitCode != expectedExit {
		return fmt.Errorf("unexpected native authentication exit status %d", result.ExitCode)
	}
	text := strings.ToLower(string(result.Stdout) + "\n" + string(result.Stderr))
	known := false
	diagnostics := []string{"is not signed", "no_pubkey", "badsig", "signatures couldn't be verified", "hash sum mismatch"}
	if artifact.Format == packaging.FormatArch {
		diagnostics = []string{"missing required signature", "invalid or corrupted package (pgp signature)", "signature from", "unknown public key", "required key missing from keyring"}
	}
	if artifact.Format == packaging.FormatRPM {
		diagnostics = []string{"is not signed", "not signed", "signature verification failed", "gpg check failed", "public key for", "package signature verification failed", "signature does not verify", "signature is not trusted"}
	}
	for _, diagnostic := range diagnostics {
		if strings.Contains(text, diagnostic) {
			known = true
			break
		}
	}
	if !known {
		return fmt.Errorf("negative package failed without recognized authentication diagnostic (exit %d)", result.ExitCode)
	}
	if err := p.assertPristine(ctx); err != nil {
		return err
	}
	return &nativeAuthRejection{Format: artifact.Format}
}

func (p *nativeGuestPackages) Close() error { return p.stopAPT() }
