//go:build linux

package packageprovider

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"

	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/advisory/feed"
)

const (
	maxOutput     = 64 << 20
	maxDiagnostic = 64 << 10
	maxPackages   = 100000
	maxPin        = 32768
)

type nativeResult struct{ stdout, stderr []byte }
type nativeRunner func(context.Context, string, []string, string, []string) (nativeResult, error)

type boundedBuffer struct {
	bytes.Buffer
	limit int
}

func (b *boundedBuffer) Write(data []byte) (int, error) {
	if len(data) > b.limit-b.Len() {
		return 0, errors.New("packageprovider: native output limit")
	}
	return b.Buffer.Write(data)
}

// runNative does not inherit user PATH, native configuration overrides or a shell.
// Each invocation is bounded even when the caller supplied no deadline. Stderr is
// retained separately: a database warning must never look like authoritative absence.
func runNative(ctx context.Context, executable string, args []string, directory string, extraEnv []string) (nativeResult, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable, args...)
	cmd.Dir = directory
	cmd.Env = append([]string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/", "LANG=C", "LC_ALL=C", "TZ=UTC", "DEBIAN_FRONTEND=noninteractive"}, extraEnv...)
	cmd.WaitDelay = time.Second
	out, diagnostic := &boundedBuffer{limit: maxOutput}, &boundedBuffer{limit: maxDiagnostic}
	cmd.Stdout, cmd.Stderr = out, diagnostic
	err := cmd.Run()
	result := nativeResult{stdout: out.Bytes(), stderr: diagnostic.Bytes()}
	if err != nil {
		return result, fmt.Errorf("packageprovider: %s: %w: %s", filepath.Base(executable), err, strings.TrimSpace(string(result.stderr)))
	}
	return result, nil
}

type database struct {
	records    map[string]*resourcev1.NativePackageRecord
	multiple   map[string]bool
	identities map[string][32]byte
	revision   []byte
}

func packageKey(p *resourcev1.PackageIdentity) string {
	return p.GetNativeName() + "/" + p.GetArchitecture()
}
func nativeVersion(v *resourcev1.NativeVersion) string {
	if r := v.GetRpm(); r != nil {
		return strconv.FormatUint(r.GetEpoch(), 10) + ":" + r.GetVersion() + "-" + r.GetRelease()
	}
	return v.GetDeb()
}
func debVersion(v string) *resourcev1.NativeVersion {
	return &resourcev1.NativeVersion{Version: &resourcev1.NativeVersion_Deb{Deb: v}}
}
func rpmVersion(epoch, version, release string) (*resourcev1.NativeVersion, error) {
	e, err := strconv.ParseUint(epoch, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("packageprovider: invalid RPM epoch: %w", err)
	}
	v := &resourcev1.NativeVersion{Version: &resourcev1.NativeVersion_Rpm{Rpm: &resourcev1.RPMVersion{Epoch: e, Version: version, Release: release}}}
	if _, err := feed.Compare("rpm", nativeVersion(v), nativeVersion(v)); err != nil {
		return nil, err
	}
	return v, nil
}

func parseDatabase(data []byte, ecosystem resourcev1.PackageEcosystem) (*database, error) {
	if len(data) == 0 || data[len(data)-1] != '\n' {
		return nil, errors.New("packageprovider: empty or truncated native database")
	}
	db := &database{records: make(map[string]*resourcev1.NativePackageRecord), multiple: make(map[string]bool)}
	rows := make([]string, 0)
	rowsByPackage := make(map[string][]string)
	seenVersions := make(map[string]bool)
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 4096), 16<<10)
	for scanner.Scan() {
		line := scanner.Text()
		if len(rows) >= maxPackages {
			return nil, errors.New("packageprovider: native database capacity")
		}
		rows = append(rows, line)
		f := strings.Split(line, "\t")
		var name, arch string
		var version *resourcev1.NativeVersion
		switch ecosystem {
		case resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_DEB:
			if len(f) != 4 || len(f[0]) != 3 {
				return nil, errors.New("packageprovider: malformed dpkg record")
			}
			name, arch = f[1], f[3]
			if !strings.ContainsRune("uihrp", rune(f[0][0])) || !strings.ContainsRune("ncHUFWti", rune(f[0][1])) || f[0][2] != ' ' {
				return nil, errors.New("packageprovider: invalid or damaged dpkg state")
			}
			// Only not-installed and residual config-files are authoritative
			// absence. Unpacked/half-installed/triggers-pending are not absence.
			if f[0][1] == 'n' || f[0][1] == 'c' {
				continue
			}
			if f[0][1] != 'i' {
				return nil, errors.New("packageprovider: incomplete dpkg database")
			}
			version = debVersion(f[2])
			if _, err := feed.Compare("dpkg", f[2], f[2]); err != nil {
				return nil, err
			}
		case resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_RPM:
			if len(f) != 5 && len(f) != 8 {
				return nil, errors.New("packageprovider: malformed rpm record")
			}
			name, arch = f[0], f[4]
			// Imported RPM signing keys have no package architecture.
			if name == "gpg-pubkey" && arch == "(none)" {
				continue
			}
			if len(f) == 8 {
				if _, err := strconv.ParseUint(f[5], 10, 64); err != nil {
					return nil, errors.New("packageprovider: invalid RPM installation time")
				}
				if _, err := strconv.ParseUint(f[6], 10, 64); err != nil {
					return nil, errors.New("packageprovider: invalid RPM installation transaction")
				}
				if len(f[7]) != 40 && len(f[7]) != 64 {
					return nil, errors.New("packageprovider: missing RPM header identity")
				}
			}
			var err error
			version, err = rpmVersion(f[1], f[2], f[3])
			if err != nil {
				return nil, err
			}
		default:
			return nil, ErrUnsupported
		}
		identity := &resourcev1.PackageIdentity{Ecosystem: ecosystem, NativeName: name, Architecture: arch}
		if err := validateMessage(identity); err != nil {
			return nil, err
		}
		key := packageKey(identity)
		versionKey := key + "\x00" + nativeVersion(version)
		if seenVersions[versionKey] {
			return nil, errors.New("packageprovider: duplicate native package version")
		}
		seenVersions[versionKey] = true
		rowsByPackage[key] = append(rowsByPackage[key], line)
		rowDigest := sha256.Sum256([]byte(line))
		if prior, exists := db.records[key]; exists {
			if ecosystem != resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_RPM || proto.Equal(prior.GetVersion(), version) {
				return nil, errors.New("packageprovider: duplicate native package row")
			}
			db.multiple[key] = true
			continue
		}
		db.records[key] = &resourcev1.NativePackageRecord{Package: identity, Version: version, NativeIdentitySha256: rowDigest[:]}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(db.records) == 0 {
		return nil, errors.New("packageprovider: incomplete empty installed database")
	}
	db.identities = make(map[string][32]byte, len(rowsByPackage))
	for key, packageRows := range rowsByPackage {
		slices.Sort(packageRows)
		db.identities[key] = sha256.Sum256([]byte(strings.Join(packageRows, "\n")))
	}
	slices.Sort(rows)
	h := sha256.New()
	_, _ = h.Write([]byte("lindm.package.database.v1\x00"))
	for _, row := range rows {
		_, _ = io.WriteString(h, row+"\n")
	}
	db.revision = h.Sum(nil)
	return db, nil
}

func (p *Provider) database(ctx context.Context) (*database, error) {
	var executable string
	var args []string
	if p.ecosystem == resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_DEB {
		executable = "/usr/bin/dpkg-query"
		args = []string{"--show", "--showformat=${db:Status-Abbrev}\t${Package}\t${Version}\t${Architecture}\n"}
		// dpkg-query can succeed against a missing/empty status database.
		var status unix.Stat_t
		if err := unix.Lstat("/var/lib/dpkg/status", &status); err != nil {
			return nil, err
		}
		if status.Mode&unix.S_IFMT != unix.S_IFREG || status.Uid != 0 || status.Mode&0022 != 0 || status.Size <= 0 || status.Size > maxOutput {
			return nil, errors.New("packageprovider: incomplete or unsafe dpkg database")
		}
		updates, err := os.ReadDir("/var/lib/dpkg/updates")
		if err != nil {
			return nil, err
		}
		for _, entry := range updates {
			if entry.Name() != "README" {
				return nil, errors.New("packageprovider: pending dpkg database updates")
			}
		}
	} else {
		executable = "/usr/bin/rpm"
		args = []string{"--query", "--all", "--queryformat", "%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\t%{INSTALLTIME}\t%{INSTALLTID}\t%{HDRID}\n"}
		var found bool
		for _, path := range []string{"/usr/lib/sysimage/rpm/rpmdb.sqlite", "/var/lib/rpm/rpmdb.sqlite"} {
			info, err := os.Stat(path)
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil {
				return nil, err
			}
			if !info.Mode().IsRegular() || info.Size() == 0 {
				return nil, errors.New("packageprovider: invalid RPM database")
			}
			found = true
			break
		}
		if !found {
			return nil, errors.New("packageprovider: RPM database unavailable")
		}
	}
	result, err := p.run(ctx, executable, args, "/", nil)
	if err != nil {
		return nil, err
	}
	if len(result.stderr) != 0 {
		return nil, errors.New("packageprovider: native database probe warned; snapshot is not complete")
	}
	return parseDatabase(result.stdout, p.ecosystem)
}

func protectedFile(path string, maximum int64) (data []byte, err error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer func() { err = errors.Join(err, f.Close()) }()
	var stat unix.Stat_t
	if err = unix.Fstat(fd, &stat); err != nil {
		return nil, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != 0 || stat.Mode&0022 != 0 || stat.Nlink != 1 || stat.Size > maximum {
		return nil, errors.New("packageprovider: unsafe native file")
	}
	data, err = io.ReadAll(io.LimitReader(f, maximum+1))
	if err == nil && int64(len(data)) > maximum {
		err = errors.New("packageprovider: native file size limit")
	}
	return data, err
}

func checkNoDowngrade(before, after *resourcev1.NativeVersion) error {
	if before == nil || after == nil {
		return nil
	}
	manager := "dpkg"
	if after.GetRpm() != nil {
		manager = "rpm"
	}
	order, err := feed.Compare(manager, nativeVersion(after), nativeVersion(before))
	if err != nil {
		return err
	}
	if order < 0 {
		return errors.New("packageprovider: implicit downgrade refused")
	}
	return nil
}

func samePackageRecord(a, b *resourcev1.NativePackageRecord) bool {
	return proto.Equal(a.GetPackage(), b.GetPackage()) && proto.Equal(a.GetVersion(), b.GetVersion())
}
