// SPDX-License-Identifier: Apache-2.0

//go:build linux

package packageprovider

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/advisory/feed"
	"lindm/internal/custody"
)

func alpmVersion(text string) (*resourcev1.NativeVersion, error) {
	if _, err := feed.Compare("pacman", text, text); err != nil {
		return nil, err
	}
	epoch := uint64(0)
	if e, rest, ok := strings.Cut(text, ":"); ok {
		var err error
		epoch, err = strconv.ParseUint(e, 10, 64)
		if err != nil {
			return nil, err
		}
		text = rest
	}
	dash := strings.LastIndexByte(text, '-')
	if dash < 1 {
		return nil, errors.New("packageprovider: incomplete ALPM version")
	}
	version := &resourcev1.NativeVersion{Version: &resourcev1.NativeVersion_Alpm{Alpm: &resourcev1.ALPMVersion{Epoch: epoch, Pkgver: text[:dash], Pkgrel: text[dash+1:]}}}
	return version, validateMessage(version)
}

// alpmDesc retains the complete local record for identity while parsing only
// the single-valued identity fields. Repeated or truncated fields are invalid.
func alpmDesc(data []byte) (*resourcev1.NativePackageRecord, error) {
	if len(data) == 0 || data[len(data)-1] != '\n' {
		return nil, ErrConflict
	}
	fields := make(map[string]string, 3)
	for _, section := range bytes.Split(data, []byte("\n\n")) {
		lines := bytes.Split(bytes.TrimSuffix(section, []byte("\n")), []byte("\n"))
		if len(lines) == 1 && len(lines[0]) == 0 {
			continue
		}
		name := string(lines[0])
		if name != "%NAME%" && name != "%VERSION%" && name != "%ARCH%" {
			continue
		}
		if len(lines) != 2 || fields[name] != "" || len(lines[1]) == 0 {
			return nil, ErrConflict
		}
		fields[name] = string(lines[1])
	}
	identity := &resourcev1.PackageIdentity{Ecosystem: resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_ALPM, NativeName: fields["%NAME%"], Architecture: fields["%ARCH%"]}
	if err := validateMessage(identity); err != nil {
		return nil, err
	}
	version, err := alpmVersion(fields["%VERSION%"])
	if err != nil {
		return nil, err
	}
	return &resourcev1.NativePackageRecord{Package: identity, Version: version}, nil
}

func alpmIdle(root string) error {
	if _, err := os.Lstat(filepath.Join(root, "db.lck")); err == nil {
		return ErrBusy
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func alpmDatabase(ctx context.Context, root string) (*database, error) {
	return alpmDatabaseGuarded(ctx, root, func() error { return alpmIdle(root) })
}

// guard is either the ordinary idle check or the retained native transaction's
// exact lock identity. No caller may merely ignore db.lck.
func alpmDatabaseGuarded(ctx context.Context, root string, guard func() error) (*database, error) {
	if err := guard(); err != nil {
		return nil, err
	}
	local := filepath.Join(root, "local")
	var before, after unix.Stat_t
	if err := unix.Lstat(local, &before); err != nil {
		return nil, err
	}
	if before.Mode&unix.S_IFMT != unix.S_IFDIR || before.Uid != 0 || before.Mode&0022 != 0 {
		return nil, ErrConflict
	}
	files, err := os.ReadDir(local)
	if err != nil {
		return nil, err
	}
	if len(files) > maxPackages+1 {
		return nil, errors.New("packageprovider: native database capacity")
	}
	db := &database{records: make(map[string]*resourcev1.NativePackageRecord), multiple: make(map[string]bool), identities: make(map[string][32]byte)}
	h := sha256.New()
	var total int
	for _, file := range files {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if file.Name() == "ALPM_DB_VERSION" && file.Type().IsRegular() {
			continue
		}
		if !file.IsDir() {
			return nil, ErrConflict
		}
		path := filepath.Join(local, file.Name(), "desc")
		data, err := custody.ReadRoot(path, 1<<20, false)
		if err != nil {
			return nil, err
		}
		total += len(data)
		if total > maxOutput {
			return nil, errors.New("packageprovider: native database capacity")
		}
		record, err := alpmDesc(data)
		if err != nil {
			return nil, err
		}
		var stat unix.Stat_t
		if err := unix.Lstat(path, &stat); err != nil {
			return nil, err
		}
		identity := sha256.New()
		_, _ = identity.Write(data)
		_, _ = fmt.Fprintf(identity, ":%d:%d:%d:%d", stat.Dev, stat.Ino, stat.Ctim.Sec, stat.Ctim.Nsec)
		digest := [32]byte(identity.Sum(nil))
		record.NativeIdentitySha256 = digest[:]
		key := packageKey(record.GetPackage())
		if db.records[key] != nil {
			return nil, ErrConflict
		}
		db.records[key], db.identities[key] = record, digest
		_, _ = h.Write(digest[:])
	}
	if len(db.records) == 0 {
		return nil, errors.New("packageprovider: incomplete empty ALPM database")
	}
	if err := unix.Lstat(local, &after); err != nil {
		return nil, err
	}
	if before.Ino != after.Ino || before.Mtim != after.Mtim || before.Ctim != after.Ctim {
		return nil, ErrConflict
	}
	if err := guard(); err != nil {
		return nil, err
	}
	db.revision = h.Sum(nil)
	return db, nil
}
