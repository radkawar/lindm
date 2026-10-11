//go:build linux

package packageprovider

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"lindm/internal/custody"

	"golang.org/x/sys/unix"

	"lindm/internal/agent/dnf"
	"lindm/internal/platform"
)

// dnf4Adapter is the fixed DNF4 Python API transaction adapter. It is executed
// only with the interpreter named by the native DNF4 entrypoint.
//
//go:embed dnf4_transaction.py
var dnf4Adapter string

type dnf4Probe struct {
	Version     string `json:"version"`
	Versionlock string `json:"versionlock"`
}

// selectDNF identifies the installed native manager; the platform registry
// only selects which generation and minimum are acceptable. DNF5 identifies
// itself by executing its CLI. The DNF4 CLI cannot run under the executor's or
// staging unit's read-only /var (it opens /var/log/hawkey.log before applying
// --setopt=logdir and exits 1), so DNF4 is identified through the dnf module
// imported by the interpreter that the native entrypoint itself names, which
// also yields the native versionlock plugin state.
func (p *Provider) selectDNF(ctx context.Context, logDirectory string) (dnf.Manager, error) {
	tooling := platform.Of(p.config.Platform).Native().Packages
	want, ok := map[platform.Backend]dnf.Kind{platform.BackendDNF4: dnf.DNF4, platform.BackendDNF5: dnf.DNF5}[tooling.Backend]
	if !ok {
		return dnf.Manager{}, fmt.Errorf("%w: platform requires its qualified mutable backend", ErrUnsupported)
	}
	selected, err := dnf.Executable(os.Stat)
	if err != nil {
		return dnf.Manager{}, err
	}
	var manager dnf.Manager
	minimum := tooling.Minimum
	if want == dnf.DNF4 {
		if manager, err = p.probeDNF4(ctx, selected); err != nil {
			return dnf.Manager{}, err
		}
	} else {
		result, err := p.run(ctx, selected, dnf.VersionArgs(logDirectory), "/", nil)
		if err != nil {
			return dnf.Manager{}, err
		}
		if manager, err = dnf.ParseVersion(result.stdout); err != nil {
			return dnf.Manager{}, err
		}
	}
	if !manager.AtLeast(want, minimum) {
		return dnf.Manager{}, fmt.Errorf("%w: native %s %s or newer required", ErrUnsupported, want, minimum)
	}
	p.managerPath, p.manager = selected, manager.Kind
	if p.rpmdb, err = rpmDatabase(); err != nil {
		return dnf.Manager{}, err
	}
	return manager, nil
}

// probeDNF4 reads the DNF4 entrypoint's interpreter and asks that interpreter's
// dnf module for its version and the native versionlock plugin state. A DNF5
// (ELF) entrypoint has no interpreter line and is refused here.
func (p *Provider) probeDNF4(ctx context.Context, entrypoint string) (dnf.Manager, error) {
	script, err := nativeEntrypoint(entrypoint)
	if err != nil {
		return dnf.Manager{}, err
	}
	if p.interpreter, err = dnf.Interpreter(script); err != nil {
		return dnf.Manager{}, err
	}
	result, err := p.run(ctx, p.interpreter, []string{"-I", "-c", dnf4Adapter, "probe"}, "/", nil)
	if err != nil {
		return dnf.Manager{}, fmt.Errorf("packageprovider: native DNF4 Python API prerequisite: %w", err)
	}
	var probe dnf4Probe
	if err := decodeClosed(result.stdout, &probe); err != nil {
		return dnf.Manager{}, err
	}
	manager, err := dnf.ParseVersion([]byte(probe.Version + "\n"))
	if err != nil {
		return dnf.Manager{}, err
	}
	switch probe.Versionlock {
	case "":
	case dnf.VersionlockListPath:
		p.versionlock = true
	default:
		return dnf.Manager{}, errors.New("packageprovider: unexpected native versionlock list")
	}
	return manager, nil
}

// decodeClosed decodes exactly one JSON value with no unknown fields.
func decodeClosed(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("packageprovider: native adapter output: %w", err)
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return errors.New("packageprovider: trailing native adapter output")
	}
	return nil
}

// dnf4 runs one adapter phase. versionlock loads the native versionlock plugin,
// exactly as the native CLI would when the plugin is natively effective.
func (p *Provider) dnf4(ctx context.Context, phase, directory string, versionlock bool, args ...string) (nativeResult, error) {
	flag := "0"
	if versionlock {
		flag = "1"
	}
	command := append([]string{"-I", "-c", dnf4Adapter, phase, directory}, args...)
	if phase == "apply" {
		// Applying mutates the system RPM database; never SIGKILL it.
		return commitNative(ctx, p.interpreter, append(command, flag), "/", nil)
	}
	return p.run(ctx, p.interpreter, append(command, flag), "/", nil)
}

// nativeEntrypoint reads the DNF4 entrypoint script. EL ships /usr/bin/dnf as a
// symlink to dnf-3; the resolved target must stay a root-owned, non-writable
// regular file in /usr/bin.
func nativeEntrypoint(path string) ([]byte, error) {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return nil, err
	}
	if filepath.Dir(resolved) != "/usr/bin" {
		return nil, errors.New("packageprovider: native DNF4 entrypoint outside /usr/bin")
	}
	var stat unix.Stat_t
	if err := unix.Lstat(resolved, &stat); err != nil {
		return nil, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != 0 || stat.Mode&0022 != 0 {
		return nil, errors.New("packageprovider: unsafe native DNF4 entrypoint")
	}
	return custody.ReadRoot(resolved, 64<<10, false)
}
