// SPDX-License-Identifier: Apache-2.0

package serverops

import (
	"archive/tar"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"
	"golang.org/x/sys/unix"
)

func decryptArchive(ctx context.Context, archive, identity string, passphrase []byte, destination string) (manifest archiveManifest, err error) {
	identities, err := loadIdentities(ctx, identity, passphrase)
	if err != nil {
		return manifest, err
	}
	cipher, _, err := openOperationFile(archive, maxArchive, true)
	if err != nil {
		return manifest, err
	}
	defer func() { err = errors.Join(err, cipher.Close()) }()
	plaintext, err := age.Decrypt(cipher, identities...)
	if err != nil {
		return manifest, errors.New("operations: archive_decryption_failed")
	}
	reader := &io.LimitedReader{R: &contextReader{ctx: ctx, reader: plaintext}, N: maxArchive + 1}
	manifest, err = extractArchive(reader, destination)
	if err != nil {
		return manifest, err
	}
	// Tar's terminator precedes the encrypted stream's authentication terminator.
	// Consume it completely so a truncated final age chunk cannot pass a drill.
	buffer := make([]byte, 32<<10)
	for {
		n, readErr := reader.Read(buffer)
		for _, value := range buffer[:n] {
			if value != 0 {
				return manifest, errors.New("operations: trailing_archive_data")
			}
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return manifest, errors.New("operations: archive_authentication_failed")
		}
	}
	if reader.N <= 0 {
		return manifest, errors.New("operations: archive_size_exceeded")
	}
	return manifest, nil
}

func extractArchive(reader io.Reader, destination string) (manifest archiveManifest, err error) {
	archive := tar.NewReader(io.LimitReader(reader, maxArchive+1))
	header, err := archive.Next()
	if err != nil {
		return manifest, err
	}
	if header.Name != "manifest.json" || header.Typeflag != tar.TypeReg || header.Size > 4<<20 {
		return manifest, errors.New("operations: invalid_archive_manifest")
	}
	decoder := json.NewDecoder(io.LimitReader(archive, 4<<20))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&manifest); err != nil {
		return manifest, errors.New("operations: invalid_archive_manifest")
	}
	if manifest.Format != 1 || manifest.CapturedAt.IsZero() || len(manifest.Files) > 65536 || manifest.ConfigPath == "" || manifest.Version == "" || manifest.SchemaMinimumRuntime < 51 || len(manifest.SchemaVersions) == 0 {
		return manifest, errors.New("operations: unsupported_archive")
	}
	if _, err = compareVersion(manifest.Version, manifest.Version); err != nil {
		return manifest, errors.New("operations: unsupported_archive_version")
	}
	for index, version := range manifest.SchemaVersions {
		if version <= 0 || (index > 0 && manifest.SchemaVersions[index-1] >= version) {
			return manifest, errors.New("operations: invalid_archive_schema")
		}
	}
	if manifest.SchemaMinimumRuntime > manifest.SchemaVersions[len(manifest.SchemaVersions)-1] {
		return manifest, errors.New("operations: invalid_archive_schema")
	}
	expected := map[string]archiveFile{"database.dump": {SHA256: manifest.DatabaseSHA256, Size: -1}}
	var total int64
	for _, file := range manifest.Files {
		if !filepath.IsAbs(file.Path) || filepath.Clean(file.Path) != file.Path || file.Size < 0 || file.Size > maxArchive || file.Mode&0022 != 0 {
			return manifest, errors.New("operations: invalid_archive_resource")
		}
		name := "files/" + strings.TrimPrefix(file.Path, "/")
		if _, ok := expected[name]; ok {
			return manifest, errors.New("operations: duplicate_archive_resource")
		}
		expected[name] = file
	}
	root, err := os.OpenRoot(destination)
	if err != nil {
		return manifest, err
	}
	defer func() { err = errors.Join(err, root.Close()) }()
	for {
		header, err = archive.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return manifest, err
		}
		file, ok := expected[header.Name]
		if !ok || header.Typeflag != tar.TypeReg || header.Size < 0 || (file.Size >= 0 && header.Size != file.Size) {
			return manifest, errors.New("operations: unexpected_archive_entry")
		}
		total += header.Size
		if total > maxArchive {
			return manifest, errors.New("operations: archive_size_exceeded")
		}
		if err = root.MkdirAll(filepath.Dir(header.Name), 0700); err != nil {
			return manifest, err
		}
		output, err := root.OpenFile(header.Name, os.O_CREATE|os.O_EXCL|os.O_WRONLY|unix.O_NOFOLLOW, 0600)
		if err != nil {
			return manifest, err
		}
		_, copyErr := io.Copy(output, archive)
		if err = errors.Join(copyErr, output.Close()); err != nil {
			return manifest, err
		}
		digest, err := digestFile(filepath.Join(destination, header.Name))
		if err != nil || digest != file.SHA256 {
			return manifest, errors.New("operations: archive_digest_mismatch")
		}
		delete(expected, header.Name)
	}
	if len(expected) != 0 {
		return manifest, errors.New("operations: incomplete_archive")
	}
	return manifest, nil
}
