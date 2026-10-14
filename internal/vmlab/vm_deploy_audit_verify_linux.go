// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"context"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"

	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/encoding/protojson"

	releasev1 "lindm/gen/lindm/release/v1"
)

const deployAuditBaselineRevision = "5e3f89dba356b98fc9c07602323a32d56eaf3929"

// openDeployAuditVerifier pins the actual executable descriptor, not a path that
// could be replaced between hashing and execution. This frozen tool is an audit
// fixture only; current release/installer verification never consumes it.
func openDeployAuditVerifier(path, expectedSHA string) (_ *os.File, err error) {
	expected, err := hex.DecodeString(expectedSHA)
	if err != nil || len(expected) != sha256.Size || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("historical audit requires an absolute verifier and independent SHA256")
	}
	file, before, err := openDeployAuditProtected(path, unix.O_RDONLY)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, file.Close())
		}
	}()
	if before.Mode&unix.S_IFMT != unix.S_IFREG || before.Mode&0077 != 0 || before.Mode&0100 == 0 || before.Uid != uint32(os.Geteuid()) || before.Nlink != 1 || before.Size <= 0 || before.Size > 256<<20 {
		return nil, errors.New("historical verifier must be a private caller-owned regular executable")
	}
	hash := sha256.New()
	if _, err = io.Copy(hash, io.LimitReader(file, before.Size+1)); err != nil {
		return nil, err
	}
	if hex.EncodeToString(hash.Sum(nil)) != expectedSHA {
		return nil, errors.New("historical verifier executable digest mismatch")
	}
	info, err := buildinfo.Read(file)
	if err != nil || info.Path != "lindm/cmd/lab" || info.Main.Path != "lindm" {
		return nil, errors.New("historical verifier must be the immutable maintained lab executable")
	}
	var after unix.Stat_t
	if err = unix.Fstat(int(file.Fd()), &after); err != nil {
		return nil, err
	}
	if before.Dev != after.Dev || before.Ino != after.Ino || before.Size != after.Size || before.Mtim != after.Mtim || before.Ctim != after.Ctim {
		return nil, errors.New("historical verifier changed during admission")
	}
	return file, nil
}

func verifyDeployAuditRelease(ctx context.Context, options VMDeployAuditOptions, directory *os.File) (_ *releasev1.ReleaseManifest, err error) {
	verifier, err := openDeployAuditVerifier(options.BaselineVerifier, options.BaselineVerifierSHA256)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, verifier.Close()) }()
	key, keyStat, err := openDeployAuditProtected(options.ReleasePublicKey, unix.O_RDONLY)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, key.Close()) }()
	if keyStat.Mode&unix.S_IFMT != unix.S_IFREG || keyStat.Nlink != 1 || keyStat.Size <= 0 || keyStat.Size > 16384 {
		return nil, errors.New("historical public release key must be a protected bounded regular file")
	}
	path := filepath.Join(deployAuditDescriptorPath(directory), "release.json")
	file, before, err := openDeployAuditManifest(path)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	command := exec.CommandContext(ctx, "/proc/self/fd/3", "release", "verify", "-directory", "/proc/self/fd/4", "-public-key", "/proc/self/fd/5", "-key-id", options.ReleaseKeyID)
	command.ExtraFiles = []*os.File{verifier, directory, key}
	command.Stdout, command.Stderr = io.Discard, io.Discard
	if err := command.Run(); err != nil {
		return nil, errors.New("immutable historical verifier rejected the signed baseline export")
	}
	// Parse only after the frozen verifier authenticated the exact manifest,
	// signatures, SBOM/provenance bindings, observations and every artifact hash.
	return readDeployAuditManifest(file, before, path)
}

func openDeployAuditManifest(path string) (*os.File, unix.Stat_t, error) {
	var stat unix.Stat_t
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, stat, err
	}
	file := os.NewFile(uintptr(fd), "authenticated historical release manifest")
	if err := unix.Fstat(fd, &stat); err != nil {
		return nil, stat, errors.Join(err, file.Close())
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Size <= 0 || stat.Size > 8<<20 || stat.Mode&0022 != 0 || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 {
		return nil, stat, errors.Join(errors.New("historical manifest must remain a protected regular file"), file.Close())
	}
	return file, stat, nil
}

func readDeployAuditManifest(file *os.File, before unix.Stat_t, path string) (*releasev1.ReleaseManifest, error) {
	data, err := io.ReadAll(io.LimitReader(file, (8<<20)+1))
	if err != nil || len(data) > 8<<20 {
		return nil, errors.Join(err, errors.New("historical manifest exceeds its bound"))
	}
	var after, current unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &after); err != nil {
		return nil, err
	}
	if err := unix.Lstat(path, &current); err != nil {
		return nil, err
	}
	if before.Dev != after.Dev || before.Ino != after.Ino || before.Size != after.Size || before.Mtim != after.Mtim || before.Ctim != after.Ctim || current.Dev != after.Dev || current.Ino != after.Ino || current.Mtim != after.Mtim || current.Ctim != after.Ctim {
		return nil, errors.New("historical manifest changed during authentication")
	}
	manifest := new(releasev1.ReleaseManifest)
	if err := protojson.Unmarshal(data, manifest); err != nil {
		return nil, errors.New("authenticated historical manifest schema mismatch")
	}
	if manifest.GetRevision() != deployAuditBaselineRevision {
		return nil, errors.New("historical audit release is not the exact immutable pre-feature source")
	}
	return manifest, nil
}
