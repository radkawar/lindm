//go:build linux

package packageprovider

import (
	"bytes"
	"context"
	"debug/elf"
	_ "embed"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/agent/nativeexec"
	"lindm/internal/custody"
	"lindm/internal/platform"
)

//go:embed alpm_transaction.py
var alpmTransactionAdapter string

const alpmProtocolCapacity = 1 << 20

type alpmAdapterEntry struct {
	Name         string `json:"name"`
	Architecture string `json:"architecture"`
	Before       string `json:"before"`
	After        string `json:"after"`
	Path         string `json:"path"`
	SHA256       string `json:"sha256"`
	Size         uint64 `json:"size"`
}

type alpmAdapterRequest struct {
	Version      string              `json:"version"`
	Architecture string              `json:"architecture"`
	Keyring      string              `json:"keyring"`
	Log          string              `json:"log"`
	Holds        map[string][]string `json:"holds"`
	Entries      []alpmAdapterEntry  `json:"entries"`
}

type alpmAdapterReply struct {
	State  string `json:"state"`
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
}

func sendALPMRequest(w io.Writer, value any) error {
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if len(encoded) == 0 || len(encoded) > alpmProtocolCapacity {
		return ErrConflict
	}
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(encoded)))
	if _, err := io.Copy(w, bytes.NewReader(size[:])); err != nil {
		return err
	}
	_, err = io.Copy(w, bytes.NewReader(encoded))
	return err
}

func readALPMReply(r io.Reader, state string) (alpmAdapterReply, error) {
	var reply alpmAdapterReply
	var size [4]byte
	if _, err := io.ReadFull(r, size[:]); err != nil {
		return reply, err
	}
	length := binary.BigEndian.Uint32(size[:])
	if length == 0 || length > alpmProtocolCapacity {
		return reply, ErrConflict
	}
	data := make([]byte, length)
	if _, err := io.ReadFull(r, data); err != nil {
		return reply, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&reply); err != nil {
		return reply, err
	}
	if err := decoder.Decode(new(any)); err != io.EOF || reply.State != state || reply.Inode == 0 {
		return reply, ErrConflict
	}
	return reply, nil
}

func (reply alpmAdapterReply) lockGuard(root string) func() error {
	return func() error {
		var stat unix.Stat_t
		if err := unix.Lstat(filepath.Join(root, "db.lck"), &stat); err != nil {
			return err
		}
		if stat.Mode&unix.S_IFMT != unix.S_IFREG || !custody.RootProtected(&stat) || stat.Dev != reply.Device || stat.Ino != reply.Inode {
			return ErrConflict
		}
		return nil
	}
}

func openALPMLibrary(abi platform.ALPMABI) (*os.File, error) {
	if abi.Path == "" || abi.SONAME == "" || abi.Version == "" {
		return nil, ErrUnsupported
	}
	file, stat, err := custody.OpenRoot(abi.Path, unix.O_RDONLY)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*os.File, error) { return nil, errors.Join(err, file.Close()) }
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Size > 16<<20 {
		return fail(ErrConflict)
	}
	library, err := elf.NewFile(file)
	if err != nil {
		return fail(err)
	}
	names, err := library.DynString(elf.DT_SONAME)
	if err != nil || library.Class != elf.ELFCLASS64 || library.Machine != elf.EM_X86_64 || len(names) != 1 || names[0] != abi.SONAME {
		return fail(errors.Join(ErrUnsupported, err))
	}
	// Keep the verified descriptor: ctypes loads /proc/self/fd/4, never a
	// second path lookup that might select a replacement library.
	return file, nil
}

func (p *Provider) executeALPM(ctx context.Context, directory string, request *agentv1.NativePackageTransactionRequest, beforeEffect func(context.Context) error) error {
	abi := platform.Of(p.config.Platform).Native().Packages.ALPM
	library, err := openALPMLibrary(abi)
	if err != nil {
		return err
	}
	defer func() { _ = library.Close() }()
	policy, err := custody.ReadRoot(filepath.Join(directory, "cache", "alpm-policy"), maxPin, false)
	if err != nil {
		return err
	}
	_, directives, ok := strings.Cut(string(policy), "\n")
	if !ok {
		return ErrConflict
	}
	spec := alpmAdapterRequest{Version: abi.Version, Architecture: request.GetSource().GetRepository().GetAlpm().GetArchitecture(), Keyring: filepath.Join(directory, "keyring"), Log: filepath.Join(directory, "pacman.log"), Holds: make(map[string][]string), Entries: make([]alpmAdapterEntry, 0, len(request.GetManifest().GetEntries()))}
	for line := range strings.SplitSeq(directives, "\n") {
		key, value, ok := strings.Cut(line, "=")
		if ok {
			spec.Holds[strings.TrimSpace(key)] = strings.Fields(value)
		}
	}
	for _, entry := range request.GetManifest().GetEntries() {
		item := alpmAdapterEntry{Name: entry.GetPackage().GetNativeName(), Architecture: entry.GetPackage().GetArchitecture(), Before: nativeVersion(entry.GetBefore()), After: nativeVersion(entry.GetAfter())}
		if artifact := entry.GetArtifact(); artifact != nil {
			item.Path, item.SHA256, item.Size = rollingArtifactPath(directory, entry), hex.EncodeToString(artifact.GetSha256()), artifact.GetSizeBytes()
		}
		spec.Entries = append(spec.Entries, item)
	}
	authorized := false
	err = runALPMAdapter(ctx, spec, library, func(ctx context.Context, connection net.Conn) error {
		ready, err := readALPMReply(connection, "ready")
		if err != nil {
			return err
		}
		guard := ready.lockGuard("/var/lib/pacman")
		before, err := alpmDatabaseGuarded(ctx, "/var/lib/pacman", guard)
		if err != nil {
			return err
		}
		manifest, plan := request.GetManifest(), request.GetPlan()
		if !bytes.Equal(before.revision, manifest.GetNativeDatabaseRevision()) || !bytes.Equal(before.revision, request.GetExpectedDatabaseRevision()) {
			return ErrConflict
		}
		if err := p.validateEntries(manifest.GetEntries(), request.GetEffectiveDesired(), before); err != nil {
			return err
		}
		if err := p.checkALPMPolicy(ctx, directory, request.GetEffectiveDesired()); err != nil {
			return err
		}
		pin, contents, err := readPin(p.pinPath(plan.GetRef()))
		if err != nil || !proto.Equal(pin, plan.GetBefore().GetNativePackage().GetPinFile()) || !bytes.Equal(contents, plan.GetBefore().GetNativePackage().GetPinContents()) {
			return errors.Join(ErrConflict, err)
		}
		if err := guard(); err != nil {
			return err
		}
		if err := beforeEffect(ctx); err != nil {
			return err
		}
		authorized = true
		if _, err := connection.Write([]byte{'C'}); err != nil {
			return err
		}
		committed, err := readALPMReply(connection, "committed")
		if err != nil || committed.Device != ready.Device || committed.Inode != ready.Inode {
			return errors.Join(ErrConflict, err)
		}
		if err := p.applyPin(plan); err != nil {
			return err
		}
		after, err := alpmDatabaseGuarded(ctx, "/var/lib/pacman", guard)
		if err != nil {
			return err
		}
		if err := transactionMatchesDatabase(manifest, before, after); err != nil {
			return err
		}
		_, err = connection.Write([]byte{'R'})
		return err
	})
	if err != nil {
		if authorized {
			return errors.Join(ErrOutcomeUnknown, err)
		}
		return err
	}
	return nil
}

func runALPMAdapter(ctx context.Context, spec alpmAdapterRequest, library *os.File, protocol func(context.Context, net.Conn) error) error {
	_, err := runALPMAdapterProgram(ctx, spec, library, alpmTransactionAdapter, protocol)
	return err
}

// The native acceptance probe uses the same transport and unchanged adapter
// under a tracing wrapper that delivers SIGTERM at exact ownership boundaries.
func runALPMAdapterProgram(ctx context.Context, spec alpmAdapterRequest, library *os.File, program string, protocol func(context.Context, net.Conn) error) (nativeResult, error) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nativeResult{}, err
	}
	parent, child := os.NewFile(uintptr(fds[0]), "alpm-authority"), os.NewFile(uintptr(fds[1]), "alpm-adapter")
	connection, err := net.FileConn(parent)
	_ = parent.Close()
	if err != nil {
		_ = child.Close()
		return nativeResult{}, err
	}
	defer func() { _ = connection.Close() }()
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { _ = connection.Close() })
	defer stop()
	done := make(chan error, 1)
	var result nativeexec.Result
	go func() {
		var err error
		result, err = nativeexec.Run(ctx, nativeexec.Command{Path: "/usr/bin/python3", Args: []string{"-I", "-c", program}, Env: []string{"HOME=/", "TZ=UTC"}, Files: []*os.File{child, library}, Timeout: 10 * time.Minute, StdoutLimit: maxOutput, StderrLimit: maxDiagnostic, TerminateOnly: true})
		_ = child.Close()
		if err != nil {
			err = fmt.Errorf("packageprovider: retained ALPM transaction: %w: %s", err, result.Diagnostic())
		}
		done <- err
	}()
	protocolErr := sendALPMRequest(connection, spec)
	if protocolErr == nil {
		protocolErr = protocol(ctx, connection)
	}
	// EOF aborts without a permit, or releases after an uncertain outcome.
	// Never SIGKILL a native transaction.
	_ = connection.Close()
	executionErr := <-done
	return nativeResult{stdout: result.Stdout, stderr: result.Stderr}, errors.Join(protocolErr, executionErr)
}
