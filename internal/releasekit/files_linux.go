// SPDX-License-Identifier: Apache-2.0
//go:build linux

package releasekit

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"filippo.io/age"
	"golang.org/x/sys/unix"

	"lindm/internal/custody"
)

func destination(path string) (string, string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", "", err
	}
	if path == "" || filepath.Clean(absolute) == "/" {
		return "", "", errors.New("releasekit: new directory required")
	}
	return filepath.Dir(absolute), filepath.Base(absolute), nil
}

// Every directory component is opened separately with NOFOLLOW. The new kit's
// parent may have normal repository permissions; the kit itself must be private.
func openDirectory(path string, private bool) (_ *os.File, err error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	for _, component := range strings.Split(strings.TrimPrefix(absolute, "/"), "/") {
		if component == "" {
			continue
		}
		next, openErr := unix.Openat(fd, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		closeErr := unix.Close(fd)
		if openErr != nil {
			return nil, errors.Join(openErr, closeErr)
		}
		fd = next
		if closeErr != nil {
			return nil, errors.Join(closeErr, unix.Close(fd))
		}
	}
	file := os.NewFile(uintptr(fd), absolute)
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return nil, errors.Join(err, file.Close())
	}
	if stat.Uid != uint32(os.Geteuid()) || (private && stat.Mode&0077 != 0) {
		return nil, errors.Join(errors.New("releasekit: directory must be operator-owned and kit mode must be 0700"), file.Close())
	}
	return file, nil
}

func readFile(directory *os.File, name string, limit int64) (_ []byte, err error) {
	fd, err := unix.Openat(int(directory.Fd()), name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("releasekit: open %s: %w", name, err)
	}
	file := os.NewFile(uintptr(fd), name)
	defer func() { err = errors.Join(err, file.Close()) }()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return nil, err
	}
	if err := safeFileStat(&stat, name, limit); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errors.New("releasekit: file grew beyond size bound")
	}
	return data, nil
}

func safeFileStat(stat *unix.Stat_t, name string, limit int64) error {
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || stat.Uid != uint32(os.Geteuid()) || stat.Mode&0077 != 0 || stat.Size <= 0 || stat.Size > limit {
		return fmt.Errorf("releasekit: %s must be an owned, bounded, non-linked regular file with mode 0600", name)
	}
	return nil
}

func readPublic(directory *os.File) (map[string][]byte, error) {
	allowed := map[string]bool{CustodyFile: true, PinsFile: true, "pins.sig": true}
	for _, name := range publicFiles {
		allowed[name] = true
	}
	entries, err := directory.ReadDir(len(allowed) + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if len(entries) != len(allowed) {
		return nil, errors.New("releasekit: incomplete kit or unexpected retained files")
	}
	for _, entry := range entries {
		if !allowed[entry.Name()] || !entry.Type().IsRegular() {
			return nil, errors.New("releasekit: unexpected or nonregular kit object")
		}
	}
	var custodyStat unix.Stat_t
	if err := unix.Fstatat(int(directory.Fd()), CustodyFile, &custodyStat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return nil, err
	}
	if err := safeFileStat(&custodyStat, CustodyFile, maxArchiveSize); err != nil {
		return nil, err
	}
	documents := make(map[string][]byte)
	for _, name := range append(append([]string{}, publicFiles...), PinsFile, "pins.sig") {
		data, err := readFile(directory, name, maxFileSize)
		if err != nil {
			return nil, err
		}
		documents[name] = data
	}
	return documents, nil
}

func writePublic(directory, name string, data []byte) (err error) {
	file, err := os.OpenFile(filepath.Join(directory, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	if _, err := file.Write(data); err != nil {
		return err
	}
	return file.Sync()
}

func syncDirectory(path string) (err error) {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	return file.Sync()
}

func archiveNames(members map[string][]byte) []string {
	names := make([]string, 0, len(members))
	for name := range members {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func archiveManifest(documents, members map[string][]byte) []byte {
	var out strings.Builder
	out.WriteString("lindm-production-custody-v1\n")
	for index, name := range keyMembers {
		fmt.Fprintf(&out, "purpose %s %s\n", name, purposes[index])
	}
	out.WriteString("purpose package-secret.asc production-package-signing\n")
	out.WriteString("purpose package-passphrase.txt production-package-signing-protection\n")
	if _, ok := members["backup-identity.txt"]; ok {
		out.WriteString("purpose backup-identity.txt production-backup-custodian\n")
	}
	for _, name := range append(append([]string{}, publicFiles...), PinsFile, "pins.sig") {
		fmt.Fprintf(&out, "public %s %s\n", name, digest(documents[name]))
	}
	for _, name := range archiveNames(members) {
		if name != "manifest.txt" {
			fmt.Fprintf(&out, "private %s %s\n", name, digest(members[name]))
		}
	}
	return []byte(out.String())
}

func readArchive(ctx context.Context, plain []byte) (_ map[string][]byte, buffers []*custody.SecretBuffer, err error) {
	members := make(map[string][]byte)
	defer func() {
		if err != nil {
			for _, buffer := range buffers {
				err = errors.Join(err, buffer.Close())
			}
		}
	}()
	allowed := map[string]bool{"manifest.txt": true, "package-secret.asc": true, "package-passphrase.txt": true, "backup-identity.txt": true}
	for _, name := range keyMembers {
		allowed[name] = true
	}
	input := bytes.NewReader(plain)
	archive := tar.NewReader(input)
	for {
		if err := ctx.Err(); err != nil {
			return nil, buffers, err
		}
		header, err := archive.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, buffers, err
		}
		if !allowed[header.Name] || members[header.Name] != nil || header.Typeflag != tar.TypeReg || header.Mode != 0600 || header.Size <= 0 || header.Size > maxFileSize || len(header.PAXRecords) != 0 || header.Linkname != "" {
			return nil, buffers, errors.New("releasekit: invalid custody archive member")
		}
		buffer, err := custody.NewSecretBuffer(int(header.Size))
		if err != nil {
			return nil, buffers, err
		}
		buffers = append(buffers, buffer)
		if _, err := io.ReadFull(archive, buffer.Bytes()); err != nil {
			return nil, buffers, err
		}
		members[header.Name] = buffer.Bytes()
	}
	remaining := plain[len(plain)-input.Len():]
	for _, value := range remaining {
		if value != 0 {
			return nil, buffers, errors.New("releasekit: unexpected archive trailer")
		}
	}
	return members, buffers, nil
}

func ageRecipient(data []byte) (*age.X25519Recipient, error) {
	if len(data) > 128 || !bytes.HasSuffix(data, []byte("\n")) {
		return nil, errors.New("releasekit: invalid backup recipient file")
	}
	return age.ParseX25519Recipient(strings.TrimSuffix(string(data), "\n"))
}

func validateArchive(documents, members map[string][]byte, pub *Public) error {
	for _, name := range append(append([]string{}, keyMembers...), "manifest.txt", "package-secret.asc", "package-passphrase.txt") {
		if len(members[name]) == 0 {
			return errors.New("releasekit: missing required custody member")
		}
	}
	if !bytes.Equal(members["manifest.txt"], archiveManifest(documents, members)) {
		return errors.New("releasekit: custody purpose or public identity binding mismatch")
	}
	keys, err := validateTrust(documents)
	if err != nil {
		return err
	}
	for index, name := range keyMembers {
		block, rest := pem.Decode(members[name])
		if block == nil || block.Type != "PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 {
			return errors.New("releasekit: invalid domain private PEM")
		}
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		clear(block.Bytes)
		if err != nil {
			return err
		}
		private, ok := parsed.(ed25519.PrivateKey)
		if !ok {
			return errors.New("releasekit: expected Ed25519 domain private key")
		}
		matches := bytes.Equal(private[ed25519.SeedSize:], keys[index])
		clear(private)
		if !matches {
			return errors.New("releasekit: domain private key disagrees with public inventory")
		}
	}
	if data, ok := members["backup-identity.txt"]; ok {
		identity, err := age.ParseX25519Identity(strings.TrimSpace(string(data)))
		if err != nil {
			return err
		}
		if identity.Recipient().String()+"\n" != string(documents[BackupRecipientFile]) {
			return errors.New("releasekit: backup identity disagreement")
		}
	}
	return validatePackageSecret(members["package-secret.asc"], members["package-passphrase.txt"], pub.PackageFingerprint)
}
