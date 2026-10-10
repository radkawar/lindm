//go:build linux

package nativefile

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	agentv1 "lindm/gen/lindm/agent/v1"
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
	c, err := openCustody(o.GetPath())
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
	program := "/usr/sbin/matchpathcon"
	info, err := os.Stat(program)
	if err != nil {
		return nil, fmt.Errorf("%w: SELinux label lookup unavailable: %w", ErrUnsupported, err)
	}
	var native unix.Stat_t
	if err := unix.Stat(program, &native); err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || native.Uid != 0 || native.Mode&0022 != 0 {
		return nil, ErrUnsafePath
	}
	lookup, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	// matchpathcon -m takes a file class name, not a numeric mode.
	command := exec.CommandContext(lookup, program, "-n", "-m", "file", "--", path)
	command.Env = []string{"LANG=C", "LC_ALL=C", "PATH=/usr/sbin:/usr/bin"}
	command.Dir = "/"
	command.WaitDelay = time.Second
	var stdout, stderr boundedOutput
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		return nil, fmt.Errorf("%w: SELinux label lookup: %w", ErrUnsupported, err)
	}
	label := strings.TrimSuffix(stdout.String(), "\n")
	if stderr.Len() != 0 || label == "" || label == "<<none>>" || strings.ContainsAny(label, "\x00\r\n\t ") || strings.Count(label, ":") < 2 {
		return nil, ErrUnsupported
	}
	return []*agentv1.NativeFileXattr{{Name: "security.selinux", Value: append([]byte(label), 0)}}, nil
}

type boundedOutput struct{ bytes.Buffer }

func (w *boundedOutput) Write(data []byte) (int, error) {
	if len(data) > 4096-w.Len() {
		return 0, ErrUnsupported
	}
	return w.Buffer.Write(data)
}
