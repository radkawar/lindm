// SPDX-License-Identifier: Apache-2.0

package serverdeps

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"time"

	serverdepsv1 "lindm/gen/lindm/serverdeps/v1"
)

// CheckRetained binds the manifest digest to bytes opened without symlinks.
func CheckRetained(root *os.File, item *serverdepsv1.File) (err error) {
	f, err := OpenRetained(root, item)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	hash := sha256.New()
	n, err := io.Copy(hash, io.LimitReader(f, int64(item.SizeBytes)+1))
	if err != nil {
		return err
	}
	if uint64(n) != item.SizeBytes || hex.EncodeToString(hash.Sum(nil)) != item.Sha256 {
		return fmt.Errorf("dependency file hash mismatch: %s", item.Path)
	}
	return nil
}

func validateRepositoryFrom(ctx context.Context, root *os.File, m *serverdepsv1.Manifest) error {
	for _, item := range m.Files {
		if err := CheckRetained(root, item); err != nil {
			return err
		}
	}
	switch m.Backend {
	case serverdepsv1.Backend_BACKEND_DEB:
		return ValidateAPT(ctx, root, m)
	case serverdepsv1.Backend_BACKEND_RPM:
		return ValidateRPM(ctx, root, m)
	default:
		return errors.New("unsupported dependency backend")
	}
}

// Install consumes only a verified closure; it never adds external repositories.
// The release signature must authenticate digest before this API is invoked.
func Install(ctx context.Context, cache, digest string) error {
	m, repository, err := Load(cache, digest)
	if err != nil {
		return err
	}
	switch m.Backend {
	case serverdepsv1.Backend_BACKEND_DEB:
		return InstallAPT(ctx, repository, m)
	case serverdepsv1.Backend_BACKEND_RPM:
		return InstallRPM(ctx, repository, m)
	default:
		return errors.New("unsupported dependency backend")
	}
}

type boundedOutput struct {
	bytes.Buffer
	remaining int
}

func (b *boundedOutput) Write(p []byte) (int, error) {
	if len(p) > b.remaining {
		return 0, errors.New("native command output exceeds bound")
	}
	b.remaining -= len(p)
	return b.Buffer.Write(p)
}

func nativeCommand(ctx context.Context, input io.Reader, extra []*os.File, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	// exec's initial lookup otherwise uses the caller's PATH before cmd.Env.
	cmd := exec.CommandContext(ctx, "/usr/bin/"+name, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", "DEBIAN_FRONTEND=noninteractive", "UCF_FORCE_CONFFOLD=1"}
	cmd.Stdin, cmd.ExtraFiles = input, extra
	out := &boundedOutput{remaining: 8 << 20}
	cmd.Stdout, cmd.Stderr = out, out
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("native %s: %w: %s", name, err, out.String())
	}
	return out.Bytes(), nil
}
