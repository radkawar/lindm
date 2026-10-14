// SPDX-License-Identifier: Apache-2.0

package reposnapshot

import (
	"context"
	"encoding/hex"
	"errors"
	"net/url"
	"os"
	"strings"
	"time"

	labv1 "lindm/gen/lindm/lab/v1"
	"lindm/internal/agent/nativeexec"
	"lindm/internal/labexec"
)

func repositoryKeys(md *repomd) (map[string]string, error) {
	keys := map[string]string{}
	for _, tag := range md.Tags {
		if !strings.HasPrefix(tag, "gpg-pubkey-") {
			continue
		}
		u, err := url.Parse(tag)
		if err != nil || u.IsAbs() || !safePath(u.Path) || strings.Contains(u.Path, "/") {
			return nil, errors.New("invalid signed RPM key location")
		}
		pin := u.Query().Get("fpr")
		decoded, err := hex.DecodeString(pin)
		if err != nil || (len(decoded) != 20 && len(decoded) != 32) || pin != strings.ToUpper(pin) || u.RawQuery != "fpr="+pin {
			return nil, errors.New("invalid signed RPM key fingerprint")
		}
		if len(keys) >= 16 || keys[u.Path] != "" {
			return nil, errors.New("RPM key count or duplicate bound")
		}
		keys[u.Path] = pin
	}
	return keys, nil
}

func verifyKeyDescriptor(ctx context.Context, key *os.File, pin string) (err error) {
	dir, err := os.MkdirTemp("", "lindm-rpm-key-")
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, os.RemoveAll(dir)) }()
	out, stderr := nativeexec.NewBuffer(64<<10), nativeexec.NewBuffer(64<<10)
	err = labexec.Run(ctx, labexec.Command{Path: "gpg", Args: []string{"--no-options", "--batch", "--homedir", dir, "--with-colons", "--show-keys", "/proc/self/fd/3"}, Files: []*os.File{key}, Stdout: out, Stderr: stderr, Timeout: 30 * time.Second})
	if err != nil {
		return err
	}
	primary, found := false, false
	for _, line := range strings.Split(out.String(), "\n") {
		fields := strings.Split(line, ":")
		if fields[0] == "pub" {
			if found {
				return errors.New("multiple signed RPM trust keys")
			}
			primary = true
		}
		if fields[0] == "fpr" && primary {
			if len(fields) < 10 || fields[9] != pin {
				return errors.New("RPM trust key differs from signed fingerprint")
			}
			found = true
			primary = false
		}
	}
	if !found || out.Truncated() || stderr.Truncated() {
		return errors.New("invalid bounded RPM trust key")
	}
	return nil
}

func verifyRPMKey(ctx context.Context, rootPath string, m *labv1.RepositorySnapshotManifest, name, pin string) error {
	root, err := openSnapshotRoot(rootPath)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	item, err := retainedFile(m, name)
	if err != nil {
		return err
	}
	return verifyRPMKeyFrom(ctx, root, item, pin)
}

func verifyRPMKeyFrom(ctx context.Context, root *os.File, item *labv1.RepositorySnapshotFile, pin string) error {
	key, err := sealRetained(root, item, maxTrustBytes)
	if err != nil {
		return err
	}
	defer func() { _ = key.Close() }()
	return verifyKeyDescriptor(ctx, key, pin)
}

// KeyPaths are trust keys authenticated directly or delegated by signed repomd.
func (c *Capture) KeyPaths() []string {
	result := []string{"repodata/repomd.xml.key"}
	for p := range c.keyPins {
		result = append(result, p)
	}
	return result
}

// OpenKey returns a bounded immutable descriptor for an authenticated native
// trust key. The caller closes the descriptor after transferring its bytes.
func (c *Capture) OpenKey(name string) (*os.File, error) {
	if _, ok := c.keyPins[name]; !ok && name != "repodata/repomd.xml.key" {
		return nil, errors.New("key is not authenticated by this snapshot")
	}
	root, err := openSnapshotRoot(c.Root)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	item, err := retainedFile(c.Manifest, name)
	if err != nil {
		return nil, err
	}
	return sealRetained(root, item, maxTrustBytes)
}
