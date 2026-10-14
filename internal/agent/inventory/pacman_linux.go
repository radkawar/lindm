// SPDX-License-Identifier: Apache-2.0

//go:build linux

package inventory

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	"google.golang.org/protobuf/proto"

	inventoryv1 "lindm/gen/lindm/inventory/v1"
)

// collectPacman reads libalpm's local database, not repository metadata. Each
// descriptor is nonblocking and no-follow; missing or changing records fail the
// entire observation rather than publishing an apparently complete partial set.
func collectPacman(ctx context.Context, path string, limits parseLimits) (_ []*inventoryv1.Package, status inventoryv1.CollectionStatus) {
	dir, err := os.OpenFile(path, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, statusFor(err)
	}
	defer func() {
		if err := dir.Close(); err != nil {
			status = statusFor(err)
		}
	}()
	before, err := dir.Stat()
	if err != nil {
		return nil, statusFor(err)
	}
	var packages []*inventoryv1.Package
	var total int64
	var records int
	for {
		if ctx.Err() != nil {
			return nil, statusFor(ctx.Err())
		}
		entries, err := dir.ReadDir(128)
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, statusFor(err)
		}
		for _, entry := range entries {
			if entry.Name() == "ALPM_DB_VERSION" && entry.Type().IsRegular() {
				continue
			}
			records++
			if records > limits.records {
				return nil, capacity
			}
			if !entry.IsDir() {
				return nil, invalid
			}
			// Open relative to the already-open directory; neither a replaced
			// parent path nor a symlink package directory can redirect the read.
			fd, openErr := syscall.Openat(int(dir.Fd()), entry.Name(), syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
			if openErr != nil {
				return nil, statusFor(openErr)
			}
			pkgdir := os.NewFile(uintptr(fd), entry.Name())
			pkg, used, readStatus := readPacmanDesc(ctx, pkgdir, limits.bytes-total)
			closeErr := pkgdir.Close()
			if readStatus != success {
				return nil, readStatus
			}
			if closeErr != nil {
				return nil, statusFor(closeErr)
			}
			total += used + int64(proto.Size(pkg)) + 6
			if total > limits.bytes {
				return nil, capacity
			}
			packages = append(packages, pkg)
		}
		if errors.Is(err, io.EOF) {
			break
		}
	}
	after, err := dir.Stat()
	if err != nil {
		return nil, statusFor(err)
	}
	if !before.ModTime().Equal(after.ModTime()) {
		return nil, invalid
	}
	slices.SortFunc(packages, func(a, b *inventoryv1.Package) int { return strings.Compare(a.Name, b.Name) })
	for i := 1; i < len(packages); i++ {
		if packages[i-1].Name == packages[i].Name {
			return nil, invalid
		}
	}
	return packages, success
}

func readPacmanDesc(ctx context.Context, dir *os.File, remaining int64) (_ *inventoryv1.Package, used int64, status inventoryv1.CollectionStatus) {
	fd, err := syscall.Openat(int(dir.Fd()), "desc", syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, 0, statusFor(err)
	}
	file := os.NewFile(uintptr(fd), filepath.Join(dir.Name(), "desc"))
	defer func() {
		if err := file.Close(); err != nil {
			status = statusFor(err)
		}
	}()
	info, err := file.Stat()
	if err != nil {
		return nil, 0, statusFor(err)
	}
	if !info.Mode().IsRegular() {
		return nil, 0, invalid
	}
	const maxDesc = 1 << 20
	if info.Size() > maxDesc || info.Size() > remaining {
		return nil, 0, capacity
	}
	limit := min(int64(maxDesc), remaining)
	reader := &io.LimitedReader{R: file, N: limit + 1}
	pkg, status := parsePacmanDesc(ctx, reader)
	used = limit + 1 - reader.N
	if reader.N == 0 {
		return nil, used, capacity
	}
	if status != success {
		return nil, used, status
	}
	after, err := file.Stat()
	if err != nil {
		return nil, used, statusFor(err)
	}
	if info.Size() != after.Size() || !info.ModTime().Equal(after.ModTime()) {
		return nil, used, invalid
	}
	return pkg, used, success
}

func parsePacmanDesc(ctx context.Context, input io.Reader) (*inventoryv1.Package, inventoryv1.CollectionStatus) {
	reader := bufio.NewReaderSize(input, maxLineBytes)
	fields := make(map[string]string, 3)
	section, value := "", ""
	count := 0
	flush := func() bool {
		if section == "%NAME%" || section == "%VERSION%" || section == "%ARCH%" {
			if count != 1 {
				return false
			}
			if _, exists := fields[section]; exists {
				return false
			}
			fields[section] = value
		}
		section, value, count = "", "", 0
		return true
	}
	for {
		if ctx.Err() != nil {
			return nil, statusFor(ctx.Err())
		}
		line, err := reader.ReadSlice('\n')
		if errors.Is(err, bufio.ErrBufferFull) {
			return nil, capacity
		}
		if errors.Is(err, io.EOF) {
			if len(line) != 0 || !flush() {
				return nil, invalid
			}
			break
		}
		if err != nil {
			return nil, invalid
		}
		text := string(line[:len(line)-1])
		if text == "" {
			if !flush() {
				return nil, invalid
			}
			continue
		}
		if section == "" {
			if len(text) < 3 || text[0] != '%' || text[len(text)-1] != '%' {
				return nil, invalid
			}
			section = text
		} else {
			value = text
			count++
		}
	}
	pkg, err := parsePackageLine(fields["%NAME%"]+"\t"+fields["%VERSION%"]+"\t"+fields["%ARCH%"], "pacman")
	if err != nil {
		return nil, invalid
	}
	return pkg, success
}
