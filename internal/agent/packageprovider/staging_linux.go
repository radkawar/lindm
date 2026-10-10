//go:build linux

package packageprovider

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	resourcev1 "lindm/gen/lindm/resource/v1"
)

//go:embed dnf_resolve.py
var dnfResolver string

type downloadDeclaration struct {
	size   uint64
	sha256 []byte
}
type dnfResolvedEntry struct {
	NEVRA        string `json:"nevra"`
	Action       string `json:"action"`
	RepoID       string `json:"repo_id"`
	DownloadSize uint64 `json:"download_size"`
	FileName     string `json:"file_name"`
}
type dnfResolved struct {
	Version int                `json:"version"`
	Entries []dnfResolvedEntry `json:"entries"`
}

func stagingUsage(directory string) (uint64, error) {
	var total uint64
	count := 0
	err := filepath.WalkDir(directory, func(path string, entry fs.DirEntry, walkErr error) error {
		if errors.Is(walkErr, os.ErrNotExist) {
			return nil
		}
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("packageprovider: symlink in staging")
		}
		info, err := entry.Info()
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || info.Size() < 0 {
			return errors.New("packageprovider: nonregular staging object")
		}
		count++
		if count > 10000 {
			return errors.New("packageprovider: staging file capacity")
		}
		if uint64(info.Size()) > 4<<30 || total > uint64(4<<30)-uint64(info.Size()) {
			return errors.New("packageprovider: staging byte capacity")
		}
		total += uint64(info.Size())
		return nil
	})
	return total, err
}
func stagingGuard(ctx context.Context, directory string, maximum uint64) (context.Context, func() error) {
	ctx, cancel := context.WithCancelCause(ctx)
	done := make(chan error, 1)
	go func() {
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				done <- context.Cause(ctx)
				return
			case <-ticker.C:
				used, err := stagingUsage(directory)
				if err == nil && used > maximum {
					err = errors.New("packageprovider: aggregate staging budget exceeded")
				}
				if err != nil {
					cancel(err)
					done <- err
					return
				}
			}
		}
	}()
	return ctx, func() error {
		used, err := stagingUsage(directory)
		if err == nil && used > maximum {
			err = errors.New("packageprovider: aggregate staging budget exceeded")
		}
		cancel(context.Canceled)
		background := <-done
		if !errors.Is(background, context.Canceled) {
			err = errors.Join(err, background)
		}
		return err
	}
}
func checkDownloadBudget(directory string, declared, maximum uint64) error {
	used, err := stagingUsage(directory)
	if err != nil {
		return err
	}
	if maximum == 0 || declared > maximum || used > maximum-declared {
		return errors.New("packageprovider: authenticated download declaration exceeds staging budget")
	}
	return reserveSpace(directory, declared+(64<<20))
}
func nativeFileLimit(maximum uint64) (func() error, error) {
	var previous unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_FSIZE, &previous); err != nil {
		return nil, err
	}
	if maximum == 0 {
		return nil, errors.New("packageprovider: empty download bound")
	}
	current := previous
	current.Cur = min(maximum, previous.Max)
	if err := unix.Setrlimit(unix.RLIMIT_FSIZE, &current); err != nil {
		return nil, err
	}
	return func() error { return unix.Setrlimit(unix.RLIMIT_FSIZE, &previous) }, nil
}
func parseAPTDownloadDeclarations(output []byte) (map[string]downloadDeclaration, uint64, error) {
	declarations := make(map[string]downloadDeclaration)
	var total uint64
	for line := range strings.SplitSeq(string(output), "\n") {
		if !strings.HasPrefix(line, "'") {
			continue
		}
		quote := strings.Index(line[1:], "'")
		if quote < 0 {
			return nil, 0, errors.New("packageprovider: malformed native URI declaration")
		}
		fields := strings.Fields(line[quote+2:])
		if len(fields) != 3 {
			return nil, 0, errors.New("packageprovider: incomplete native archive declaration")
		}
		name := fields[0]
		if filepath.Base(name) != name || !strings.HasSuffix(name, ".deb") {
			return nil, 0, ErrConflict
		}
		size, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil || size == 0 || size > 512<<20 {
			return nil, 0, errors.New("packageprovider: archive declared size invalid")
		}
		checksum, ok := strings.CutPrefix(fields[2], "SHA256:")
		if !ok {
			return nil, 0, errors.New("packageprovider: native archive declaration must use SHA256")
		}
		digest, err := hex.DecodeString(checksum)
		if err != nil || len(digest) != 32 {
			return nil, 0, errors.New("packageprovider: invalid declared archive digest")
		}
		if _, duplicate := declarations[name]; duplicate {
			return nil, 0, ErrConflict
		}
		if total > (512<<20)-size {
			return nil, 0, errors.New("packageprovider: archive declared aggregate too large")
		}
		total += size
		declarations[name] = downloadDeclaration{size: size, sha256: digest}
	}
	return declarations, total, nil
}
func (p *Provider) resolveDNFSizes(ctx context.Context, directory, operation string, d *resourcev1.NativePackageDesired) (*dnfResolved, uint64, error) {
	result, err := p.run(ctx, "/usr/bin/python3", []string{"-I", "-c", dnfResolver, directory, operation, dnfSpec(d)}, "/", nil)
	if err != nil {
		return nil, 0, fmt.Errorf("packageprovider: python3-libdnf5 native resolver prerequisite: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(result.stdout))
	decoder.DisallowUnknownFields()
	resolved := new(dnfResolved)
	if err := decoder.Decode(resolved); err != nil {
		return nil, 0, err
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return nil, 0, errors.New("packageprovider: trailing native resolver output")
	}
	if resolved.Version != 1 || len(resolved.Entries) > 8192 {
		return nil, 0, ErrUnsupported
	}
	var total uint64
	seen := make(map[string]bool)
	for _, entry := range resolved.Entries {
		identity, _, err := parseNEVRA(entry.NEVRA)
		if err != nil {
			return nil, 0, err
		}
		if seen[entry.NEVRA] {
			return nil, 0, ErrConflict
		}
		seen[entry.NEVRA] = true
		switch entry.Action {
		case "Install", "Upgrade":
			if entry.DownloadSize == 0 || entry.DownloadSize > 512<<20 || total > (512<<20)-entry.DownloadSize {
				return nil, 0, errors.New("packageprovider: invalid native download declaration")
			}
			total += entry.DownloadSize
		case "Remove":
			if operation != "remove" || packageKey(identity) != packageKey(d.GetPackage()) {
				return nil, 0, errors.New("packageprovider: native solver removes unrequested package")
			}
		case "Replaced":
		default:
			return nil, 0, ErrUnsupported
		}
	}
	return resolved, total, nil
}
func matchDNFDeclaration(resolved *dnfResolved, transaction *dnfTransaction) error {
	if len(resolved.Entries) != len(transaction.RPMs) {
		return errors.New("packageprovider: DNF solver changed after download precheck")
	}
	for _, rpm := range transaction.RPMs {
		found := false
		identity, version, err := parseNEVRA(rpm.NEVRA)
		if err != nil {
			return err
		}
		for _, entry := range resolved.Entries {
			other, otherVersion, err := parseNEVRA(entry.NEVRA)
			if err != nil {
				return err
			}
			if packageKey(identity) == packageKey(other) && nativeVersion(version) == nativeVersion(otherVersion) && entry.Action == rpm.Action {
				found = true
				break
			}
		}
		if !found {
			return errors.New("packageprovider: undeclared native DNF package")
		}
	}
	return nil
}

// Native managers may download concurrently. RLIMIT_FSIZE bounds every child
// file by the largest declared artifact (or preexisting native cache file), and
// the watcher enforces each package's smaller individual declaration. This is
// active bounded staging, not an atomic filesystem quota.
func boundedDownload(ctx context.Context, directory string, declarations map[string]downloadDeclaration, run func(context.Context) error) (resultErr error) {
	if len(declarations) == 0 {
		return run(ctx)
	}
	var maximum uint64
	for _, declaration := range declarations {
		maximum = max(maximum, declaration.size)
	}
	if err := filepath.WalkDir(directory, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Size() > 0 {
			maximum = max(maximum, uint64(info.Size()))
		}
		return nil
	}); err != nil {
		return err
	}
	restore, err := nativeFileLimit(maximum)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, restore()) }()
	check := func() error {
		return filepath.WalkDir(directory, func(path string, entry fs.DirEntry, walkErr error) error {
			if errors.Is(walkErr, os.ErrNotExist) {
				return nil
			}
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() {
				return nil
			}
			name := entry.Name()
			if !strings.HasSuffix(name, ".deb") && !strings.HasSuffix(name, ".rpm") {
				return nil
			}
			declaration, ok := declarations[name]
			if !ok {
				return errors.New("packageprovider: undeclared package download")
			}
			info, err := entry.Info()
			if errors.Is(err, os.ErrNotExist) {
				return nil
			}
			if err != nil {
				return err
			}
			if info.Size() < 0 || uint64(info.Size()) > declaration.size {
				return errors.New("packageprovider: package download exceeds declaration")
			}
			return nil
		})
	}
	ctx, cancel := context.WithCancelCause(ctx)
	done := make(chan error, 1)
	go func() {
		ticker := time.NewTicker(50 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				done <- context.Cause(ctx)
				return
			case <-ticker.C:
				if err := check(); err != nil {
					cancel(err)
					done <- err
					return
				}
			}
		}
	}()
	resultErr = run(ctx)
	if err := check(); err != nil {
		resultErr = errors.Join(resultErr, err)
	}
	cancel(context.Canceled)
	if err := <-done; !errors.Is(err, context.Canceled) {
		resultErr = errors.Join(resultErr, err)
	}
	return resultErr
}
