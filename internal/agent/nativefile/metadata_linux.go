//go:build linux

package nativefile

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/agent/nativeexec"
)

// CreationMetadata derives the label of the final pathname from native SELinux
// policy, never from the temporary sibling's name or a server-provided label.
// Existing file updates/restoration copy their exact protected prior xattrs.
// ACLs, capabilities, IMA/EVM and unsupported metadata fail closed elsewhere.
func CreationMetadata(ctx context.Context, target *agentv1.ResourceOwnershipSnapshot) (err error) {
	o := target.GetObservation().GetManagedFile()
	if o == nil || !o.GetExists() || o.GetFile() == nil {
		return ErrUnsupported
	}
	c, err := openCustody(o.GetPath(), false)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, c.close()) }()
	if c.file != nil {
		return ErrConflict
	}
	if err := noDefaultACL(c.parent()); err != nil {
		return err
	}
	target.ManagedFileXattrs, err = CreationXattrs(ctx, o.GetPath())
	if err != nil {
		return err
	}
	o.SecurityMetadataSha256 = XattrDigest(target.GetManagedFileXattrs())
	return c.unchanged()
}

// CreationXattrs is read-only native label derivation for providers that own
// exact parent creation. It does not approve ancestry, ACLs, or any write.
func CreationXattrs(ctx context.Context, path string) ([]*agentv1.NativeFileXattr, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" || strings.ContainsAny(path, "\x00\r\n") {
		return nil, ErrUnsafePath
	}
	_, err := os.Stat("/sys/fs/selinux/enforce")
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	// Fixed native policy lookup, not a configurable command or interpreter.
	// A helper with SELinux enabled but no lookup tool refuses new files.
	// matchpathcon -m takes a file class name, not a numeric mode.
	result, err := nativeexec.Run(ctx, nativeexec.Command{Path: "/usr/sbin/matchpathcon", Args: []string{"-n", "-m", "file", "--", path}, Timeout: 5 * time.Second, StdoutLimit: 4096, StderrLimit: 4096})
	if err != nil {
		return nil, fmt.Errorf("%w: SELinux label lookup: %w", ErrUnsupported, err)
	}
	label := strings.TrimSuffix(string(result.Stdout), "\n")
	if len(result.Stderr) != 0 || label == "" || label == "<<none>>" || strings.ContainsAny(label, "\x00\r\n\t ") || strings.Count(label, ":") < 2 {
		return nil, ErrUnsupported
	}
	return []*agentv1.NativeFileXattr{{Name: "security.selinux", Value: append([]byte(label), 0)}}, nil
}
