// SPDX-License-Identifier: Apache-2.0
//go:build linux

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"

	"golang.org/x/sys/unix"

	"lindm/internal/custody"
	"lindm/internal/releasebuild"
	"lindm/internal/releasekit"
)

func runVerify(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("release verify", flag.ContinueOnError)
	flags.SetOutput(stderr)
	directory := flags.String("directory", "artifacts/release", "bundle directory to authenticate")
	keys := flags.String("keys", "release-keys", "independent operator public trust directory; no unlock needed")
	publicKey := flags.String("public-key", "", "independently obtained public attestation key instead of a key kit")
	keyID := flags.String("key-id", "", "independently authenticated SPKI SHA256 pin; required with --public-key")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || ((*publicKey == "") != (*keyID == "")) {
		return errors.New("verify takes no positional arguments; --public-key and --key-id must be supplied together")
	}
	if *publicKey == "" {
		public, err := releasekit.Load(*keys)
		if err != nil {
			return err
		}
		*publicKey = filepath.Join(*keys, "attestation.pub")
		*keyID = public.AttestationKeyID
	}
	if err := verifyWithPublicKey(ctx, *directory, *publicKey, *keyID); err != nil {
		return err
	}
	_, err := fmt.Fprintln(stdout, "Verified production release and installer:", *directory)
	return err
}

func verifyBundle(ctx context.Context, directory, keys string, public *releasekit.Public) error {
	return verifyWithPublicKey(ctx, directory, filepath.Join(keys, "attestation.pub"), public.AttestationKeyID)
}

func verifyWithPublicKey(ctx context.Context, directory, publicKey, keyID string) error {
	manifest, err := releasebuild.Verify(ctx, directory, publicKey, keyID)
	if err != nil {
		return err
	}
	if manifest.GetCustody() != "production" {
		return errors.New("development releases are not production bundles")
	}
	return releasebuild.VerifyInstaller(ctx, directory, publicKey, keyID)
}

func readRegular(path string, limit int64) (data []byte, err error) {
	file, err := os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > limit {
		return nil, errors.New("expected bounded regular file")
	}
	data, err = io.ReadAll(io.LimitReader(file, limit+1))
	if int64(len(data)) > limit {
		return nil, errors.New("file exceeded bound")
	}
	return data, err
}

func readPassphrase(ctx context.Context, fd int, confirm bool) (*custody.SecretBuffer, error) {
	plain, err := custody.ReadPassphrase(ctx, fd, confirm)
	if err != nil {
		return nil, err
	}
	defer clear(plain)
	buffer, err := custody.NewSecretBuffer(len(plain))
	if err != nil {
		return nil, err
	}
	copy(buffer.Bytes(), plain)
	return buffer, nil
}

func readIdentity(ctx context.Context, fd int) (*custody.SecretBuffer, error) {
	// age X25519 identities fit the same bounded, single-line protected-pipe
	// contract. Parsing happens in Unlock; identity files are never admitted.
	return readPassphrase(ctx, fd, false)
}

func absolutePaths(paths ...*string) error {
	for _, path := range paths {
		absolute, err := filepath.Abs(*path)
		if err != nil {
			return err
		}
		*path = absolute
	}
	return nil
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func writeSHA256SUMS(directory string) (err error) {
	var names []string
	if err := filepath.WalkDir(directory, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		if !entry.Type().IsRegular() {
			return errors.New("bundle contains a link or special file")
		}
		relative, err := filepath.Rel(directory, path)
		if err != nil {
			return err
		}
		names = append(names, filepath.ToSlash(relative))
		return nil
	}); err != nil {
		return err
	}
	sort.Strings(names)
	output, err := os.OpenFile(filepath.Join(directory, "SHA256SUMS"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, output.Close()) }()
	for _, name := range names {
		input, err := os.OpenFile(filepath.Join(directory, name), os.O_RDONLY|unix.O_NOFOLLOW, 0)
		if err != nil {
			return err
		}
		hash := sha256.New()
		_, copyErr := io.Copy(hash, input)
		if err := errors.Join(copyErr, input.Close()); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(output, "%x  %s\n", hash.Sum(nil), name); err != nil {
			return err
		}
	}
	return output.Sync()
}
