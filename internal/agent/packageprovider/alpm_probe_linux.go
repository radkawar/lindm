// SPDX-License-Identifier: Apache-2.0

//go:build linux

package packageprovider

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"

	"golang.org/x/sys/unix"

	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/custody"
	"lindm/internal/platform"
)

// ProbeALPMNativeLock is a disposable-guest acceptance probe, not an execution
// authority. It uses the production adapter's real native prepare/abort path,
// never sends C (the effect permit), and tries a real competing pacman frontend
// while readiness is held. The ordinary signed resource lane independently
// qualifies authorized package effects.
func ProbeALPMNativeLock(ctx context.Context, product *resourcev1.PlatformProduct, fixtureRoot, archive string) ([]byte, error) {
	if os.Geteuid() != 0 || platform.Of(product).Native().Packages.Backend != platform.BackendPacman || filepath.Dir(archive) != filepath.Join(fixtureRoot, "repo") {
		return nil, ErrUnsupported
	}
	// The fixture root also holds the lab's local-user homes, so it is
	// traversable (0755); root protection of it and its whole ancestry keeps
	// the probe's archive, keyring and log root-controlled.
	root, stat, err := custody.OpenRoot(fixtureRoot, unix.O_PATH|unix.O_DIRECTORY)
	if err != nil {
		return nil, err
	}
	if err := root.Close(); err != nil {
		return nil, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR {
		return nil, fmt.Errorf("%w: fixture root is not a directory: %s", custody.ErrUnsafe, fixtureRoot)
	}
	if _, err := artifactFor(archive); err != nil {
		return nil, err
	}
	p := &Provider{config: Config{Platform: product}, ecosystem: resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_ALPM}
	if err := p.checkPlatform(); err != nil {
		return nil, err
	}
	abi := platform.Of(product).Native().Packages.ALPM
	library, err := openALPMLibrary(abi)
	if err != nil {
		return nil, err
	}
	defer func() { _ = library.Close() }()
	before, err := alpmDatabase(ctx, "/var/lib/pacman")
	if err != nil {
		return nil, err
	}
	spec := alpmAdapterRequest{Version: abi.Version, Architecture: product.GetArchitecture(), Keyring: filepath.Join(fixtureRoot, "gnupg"), Log: filepath.Join(fixtureRoot, "lock-probe.log"), Holds: map[string][]string{}, Entries: []alpmAdapterEntry{}}
	var diagnostic []byte
	err = runALPMAdapter(ctx, spec, library, func(ctx context.Context, connection net.Conn) error {
		ready, err := readALPMReply(connection, "ready")
		if err != nil {
			return err
		}
		guard := ready.lockGuard("/var/lib/pacman")
		locked, err := alpmDatabaseGuarded(ctx, "/var/lib/pacman", guard)
		if err != nil || !bytes.Equal(before.revision, locked.revision) {
			return errors.Join(ErrConflict, err)
		}
		result, competeErr := commitNative(ctx, "/usr/bin/pacman", []string{"--dbpath", "/var/lib/pacman", "--gpgdir", spec.Keyring, "--logfile", filepath.Join(fixtureRoot, "competing-pacman.log"), "--noconfirm", "--color", "never", "-U", "--", archive}, "/", nil)
		diagnostic = append(bytes.Clone(result.stdout), result.stderr...)
		if competeErr == nil || !bytes.Contains(diagnostic, []byte("unable to lock database")) {
			return errors.New("packageprovider: competing pacman did not refuse the held native lock")
		}
		// A failed adapter acquisition must not release the outer owner's lock.
		refusal, refuseErr := runALPMAdapterProgram(ctx, spec, library, alpmTransactionAdapter, func(_ context.Context, conn net.Conn) error {
			_, err := readALPMReply(conn, "ready")
			return err
		})
		if refuseErr == nil || !bytes.Contains(refusal.stderr, []byte("native ALPM lock acquisition refused")) {
			return errors.New("packageprovider: second adapter did not refuse the owned native lock")
		}
		after, err := alpmDatabaseGuarded(ctx, "/var/lib/pacman", guard)
		if err != nil || !bytes.Equal(before.revision, after.revision) {
			return errors.Join(ErrConflict, err)
		}
		if _, err := connection.Write([]byte{'A'}); err != nil {
			return err
		}
		aborted, err := readALPMReply(connection, "aborted")
		if err != nil || aborted.Device != ready.Device || aborted.Inode != ready.Inode {
			return errors.Join(ErrConflict, err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	after, err := alpmDatabase(ctx, "/var/lib/pacman")
	if err != nil || !bytes.Equal(before.revision, after.revision) {
		return nil, errors.Join(ErrConflict, err)
	}
	if err := probeALPMCancellation(ctx, spec, library, before); err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		ABI                      string    `json:"abi"`
		CompetingPacmanRefused   bool      `json:"competingPacmanRefused"`
		EffectPermitSent         bool      `json:"effectPermitSent"`
		CancellationBoundaries   [3]string `json:"cancellationBoundaries"`
		SubsequentPacmanAcquired bool      `json:"subsequentPacmanAcquired"`
		DatabaseSHA256           string    `json:"databaseSha256"`
		NativeDiagnostic         string    `json:"nativeDiagnostic"`
	}{ABI: abi.Version, CompetingPacmanRefused: true, EffectPermitSent: false, CancellationBoundaries: [3]string{"acquire", "cleanup", "ready-context"}, SubsequentPacmanAcquired: true, DatabaseSHA256: hex.EncodeToString(after.revision), NativeDiagnostic: string(diagnostic)})
}

func probeALPMCancellation(ctx context.Context, spec alpmAdapterRequest, library *os.File, baseline *database) error {
	for _, boundary := range []string{"acquire", "cleanup", "ready-context"} {
		readySeen := false
		childCtx, cancel := context.WithCancel(ctx)
		program := alpmTransactionAdapter
		if boundary != "ready-context" {
			program = alpmCancellationProgram(boundary)
		}
		result, runErr := runALPMAdapterProgram(childCtx, spec, library, program, func(_ context.Context, connection net.Conn) error {
			ready, err := readALPMReply(connection, "ready")
			if err != nil {
				return err
			}
			readySeen = true
			if boundary == "acquire" {
				return errors.New("packageprovider: canceled acquisition reached readiness")
			}
			if boundary == "ready-context" {
				cancel()
				return childCtx.Err()
			}
			if _, err := connection.Write([]byte{'A'}); err != nil {
				return err
			}
			aborted, err := readALPMReply(connection, "aborted")
			if err != nil || aborted.Device != ready.Device || aborted.Inode != ready.Inode {
				return errors.Join(ErrConflict, err)
			}
			return nil
		})
		cancel()
		var witness struct {
			Boundary      string `json:"boundary"`
			LockPresent   bool   `json:"lockPresent"`
			RecordedOwner bool   `json:"recordedOwner"`
			SignalSent    bool   `json:"signalSent"`
		}
		if boundary == "ready-context" {
			if !readySeen || !errors.Is(runErr, context.Canceled) {
				return errors.Join(errors.New("packageprovider: native context cancellation was not observed"), runErr)
			}
		} else if json.Unmarshal(result.stdout, &witness) != nil || witness.Boundary != boundary || !witness.LockPresent || !witness.SignalSent || witness.RecordedOwner != (boundary == "cleanup") {
			return errors.Join(errors.New("packageprovider: native cancellation boundary was not witnessed"), runErr)
		}
		if (boundary == "acquire" && (runErr == nil || readySeen)) || (boundary == "cleanup" && runErr != nil) {
			return errors.Join(errors.New("packageprovider: native cancellation protocol changed"), runErr)
		}
		after, err := alpmDatabase(ctx, "/var/lib/pacman")
		if err != nil || !bytes.Equal(baseline.revision, after.revision) {
			return errors.Join(ErrConflict, err)
		}
		// pacman_remove initializes a real locked transaction before resolving
		// targets. A missing target aborts it before prepare/commit; --print is
		// intentionally NOT used because pacman makes it a NOLOCK transaction.
		const absent = "/lindm-native-lock-probe-absent"
		result, err = commitNative(ctx, "/usr/bin/pacman", []string{"--dbpath", "/var/lib/pacman", "--logfile", spec.Log, "--noconfirm", "--color", "never", "-R", "--", absent}, "/", nil)
		if err == nil || !bytes.Contains(result.stderr, []byte("target not found: "+absent)) || bytes.Contains(result.stderr, []byte("unable to lock database")) {
			return errors.New("packageprovider: subsequent pacman did not acquire and release the native transaction")
		}
		after, err = alpmDatabase(ctx, "/var/lib/pacman")
		if err != nil || !bytes.Equal(baseline.revision, after.revision) {
			return errors.Join(ErrConflict, err)
		}
	}
	return nil
}

// Instrument the unchanged production helper, not a replacement/fake libalpm.
// AST-selected line events inject a real signal after successful trans_init
// but before ownership assignment, or immediately before native abort cleanup.
// Every injected transaction is empty and the caller can send only A, never C.
func alpmCancellationProgram(boundary string) string {
	return "import ast as _probe_ast, os as _probe_os, signal as _probe_signal, sys as _probe_sys, json as _probe_json, stat as _probe_stat\n" +
		"_probe_source = " + strconv.Quote(alpmTransactionAdapter) + "\n_probe_boundary = " + strconv.Quote(boundary) + "\n" + `
_probe_lines = []
for _probe_node in _probe_ast.walk(_probe_ast.parse(_probe_source)):
    if _probe_boundary == "acquire" and isinstance(_probe_node, _probe_ast.Assign):
        if any(isinstance(t, _probe_ast.Name) and t.id == "locked" for t in _probe_node.targets) and isinstance(_probe_node.value, _probe_ast.Constant) and _probe_node.value.value is True:
            _probe_lines.append(_probe_node.lineno)
    if _probe_boundary == "cleanup" and isinstance(_probe_node, _probe_ast.Call):
        if isinstance(_probe_node.func, _probe_ast.Name) and _probe_node.func.id == "trans_release":
            _probe_lines.append(_probe_node.lineno)
assert len(_probe_lines) == 1, "native cancellation instrumentation boundary changed"
_probe_fired = False
def _probe_trace(frame, event, arg):
    global _probe_fired
    if not _probe_fired and event == "line" and frame.f_code.co_filename == "lindm-alpm-adapter" and frame.f_lineno == _probe_lines[0]:
        _probe_fired = True
        lock = _probe_os.stat("/var/lib/pacman/db.lck", follow_symlinks=False)
        witness = {"boundary": _probe_boundary, "lockPresent": _probe_stat.S_ISREG(lock.st_mode) and lock.st_uid == 0, "recordedOwner": frame.f_globals["locked"], "signalSent": True}
        _probe_os.kill(_probe_os.getpid(), _probe_signal.SIGTERM)
        _probe_os.write(1, _probe_json.dumps(witness, separators=(",", ":")).encode())
    return _probe_trace
_probe_sys.settrace(_probe_trace)
exec(compile(_probe_source, "lindm-alpm-adapter", "exec"))
`
}
