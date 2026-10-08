//go:build linux

// Package config loads the agent protobuf configuration and resolves the
// network account once per process. It does not open executor state.
package config

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

	"buf.build/go/protovalidate"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/encoding/protojson"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/protodata"
)

const (
	maxFileBytes = 1 << 20

	// ExecutorConfigPath is the packaged executor configuration. The executor
	// unit passes no arguments.
	ExecutorConfigPath = "/etc/lindm/executor.json"
	// NetworkConfigPath is the packaged network-process configuration. It is
	// the same AgentConfig document, not a second schema.
	NetworkConfigPath = "/etc/lindm/agent.json"
)

// Document is a validated configuration with paths and the frozen network UID.
type Document struct {
	Proto            *agentv1.AgentConfig
	StateDirectory   string
	RuntimeDirectory string
	SpoolDirectory   string
	SocketName       string
	SocketPath       string
	NetworkUser      string
	NetworkUID       uint32
	NetworkGID       uint32
}

// Load decodes configuration, requires a root-owned file with non-replaceable
// root-owned ancestry, and resolves network_user once. Relative paths use the
// configuration directory.
func Load(path string) (*Document, error) {
	return load(path, true)
}

func load(path string, rootOwner bool) (*Document, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve configuration path: %w", err)
	}
	data, err := readConfig(absolute, rootOwner)
	if err != nil {
		return nil, fmt.Errorf("read configuration: %w", err)
	}
	cfg := &agentv1.AgentConfig{}
	if err := (protojson.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("decode configuration: %w", err)
	}
	if err := protodata.ValidateClosed(cfg.ProtoReflect()); err != nil {
		return nil, errors.New("unknown configuration fields")
	}
	validator, err := protovalidate.New(protovalidate.WithMessages(cfg), protovalidate.WithDisableLazy())
	if err != nil {
		return nil, fmt.Errorf("compile configuration validation rules: %w", err)
	}
	if err := validator.Validate(cfg); err != nil {
		return nil, fmt.Errorf("validate configuration: %w", err)
	}
	base := filepath.Dir(absolute)
	stateDir, err := canonicalDirectory(resolve(base, cfg.GetStateDirectory()))
	if err != nil {
		return nil, fmt.Errorf("state directory: %w", err)
	}
	runtimeDir, err := canonicalDirectory(resolve(base, cfg.GetRuntimeDirectory()))
	if err != nil {
		return nil, fmt.Errorf("runtime directory: %w", err)
	}
	spoolDir, err := canonicalDirectory(resolve(base, cfg.GetSpoolDirectory()))
	if err != nil {
		return nil, fmt.Errorf("spool directory: %w", err)
	}
	if err := distinctDirectories(stateDir, runtimeDir, spoolDir); err != nil {
		return nil, err
	}
	socket, err := socketPath(runtimeDir, cfg.GetSocketName())
	if err != nil {
		return nil, err
	}
	uid, gid, name, err := resolveNetworkUser(cfg.GetNetworkUser())
	if err != nil {
		return nil, err
	}
	return &Document{
		Proto:            cfg,
		StateDirectory:   stateDir,
		RuntimeDirectory: runtimeDir,
		SpoolDirectory:   spoolDir,
		SocketName:       cfg.GetSocketName(),
		SocketPath:       socket,
		NetworkUser:      name,
		NetworkUID:       uid,
		NetworkGID:       gid,
	}, nil
}

func resolve(base, path string) string {
	if filepath.IsAbs(path) {
		return filepath.Clean(path)
	}
	return filepath.Clean(filepath.Join(base, path))
}

func canonicalDirectory(path string) (string, error) {
	cleaned := filepath.Clean(path)
	if !filepath.IsAbs(cleaned) || cleaned == string(filepath.Separator) {
		return "", errors.New("path must be an absolute non-root directory")
	}
	info, err := os.Lstat(cleaned)
	if errors.Is(err, os.ErrNotExist) {
		return cleaned, nil
	}
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", errors.New("path must be a canonical directory")
	}
	resolved, err := filepath.EvalSymlinks(cleaned)
	if err != nil {
		return "", err
	}
	if filepath.Clean(resolved) != cleaned {
		return "", errors.New("path is not canonical")
	}
	return cleaned, nil
}

func distinctDirectories(paths ...string) error {
	for i := range paths {
		for j := i + 1; j < len(paths); j++ {
			if paths[i] == paths[j] || nestedPath(paths[i], paths[j]) {
				return errors.New("state, runtime, and spool directories must be distinct")
			}
		}
	}
	return nil
}

func nestedPath(parent, child string) bool {
	rel, err := filepath.Rel(parent, child)
	if err != nil {
		return true
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func socketPath(directory, name string) (string, error) {
	if name == "" || name != filepath.Base(name) || filepath.IsAbs(name) {
		return "", errors.New("invalid executor socket name")
	}
	path := filepath.Join(directory, name)
	if filepath.Dir(path) != filepath.Clean(directory) {
		return "", errors.New("executor socket escapes the runtime directory")
	}
	// sockaddr_un.sun_path is 108 bytes including the terminating NUL.
	if len(path) >= 108 {
		return "", errors.New("executor socket path exceeds the unix address length")
	}
	return path, nil
}

// readConfig walks descriptor-relative and rejects a symlink, hardlink, or
// replaceable parent. Production ancestry is root-owned. A network-owned
// parent cannot pass, including when that network process is the reader.
func readConfig(path string, rootOwner bool) (_ []byte, err error) {
	fd, err := openConfig(path, rootOwner)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "agent-config")
	defer func() { err = errors.Join(err, file.Close()) }()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return nil, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 {
		return nil, errors.New("configuration must be a regular non-hardlinked file")
	}
	if !ownerAllowed(stat.Uid, os.Geteuid(), rootOwner) {
		return nil, errors.New("configuration must be root-owned")
	}
	if stat.Mode&0022 != 0 {
		return nil, errors.New("configuration must not be group- or world-writable")
	}
	if stat.Size > maxFileBytes {
		return nil, errors.New("configuration exceeds 1 MiB")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxFileBytes {
		return nil, errors.New("configuration exceeds 1 MiB")
	}
	return data, nil
}

func openConfig(path string, rootOwner bool) (int, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return -1, err
	}
	absolute = filepath.Clean(absolute)
	if !filepath.IsAbs(absolute) {
		return -1, errors.New("configuration path is not absolute")
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY, 0)
	if err != nil {
		return -1, err
	}
	parts := strings.Split(strings.TrimPrefix(absolute, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		_ = unix.Close(fd)
		return -1, errors.New("configuration path is not a file")
	}
	for i, component := range parts {
		if component == "" || component == "." || component == ".." {
			_ = unix.Close(fd)
			return -1, errors.New("configuration path is not canonical")
		}
		var info unix.Stat_t
		if err := unix.Fstat(fd, &info); err != nil {
			_ = unix.Close(fd)
			return -1, err
		}
		if err := trustedConfigAncestor(info, rootOwner); err != nil {
			_ = unix.Close(fd)
			return -1, err
		}
		flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC
		if i == len(parts)-1 {
			flags |= unix.O_NONBLOCK
		} else {
			flags |= unix.O_DIRECTORY
		}
		next, err := unix.Openat(fd, component, flags, 0)
		_ = unix.Close(fd)
		if err != nil {
			return -1, err
		}
		fd = next
	}
	return fd, nil
}

func trustedConfigAncestor(info unix.Stat_t, rootOwner bool) error {
	if info.Mode&unix.S_IFMT != unix.S_IFDIR {
		return errors.New("configuration ancestor is not a directory")
	}
	if rootOwner {
		// Root ownership excludes the network account. Group/world write would
		// let that account replace a later path component.
		if info.Uid != 0 || info.Mode&0022 != 0 {
			return errors.New("configuration ancestry must be root-owned and not replaceable")
		}
		return nil
	}
	if info.Uid != 0 && info.Uid != uint32(os.Geteuid()) {
		return errors.New("configuration ancestry has an untrusted owner")
	}
	if info.Mode&0022 != 0 && info.Mode&unix.S_ISVTX == 0 {
		return errors.New("configuration ancestry is replaceable")
	}
	return nil
}

func ownerAllowed(owner uint32, euid int, rootOwner bool) bool {
	if rootOwner {
		return owner == 0
	}
	return owner == 0 || owner == uint32(euid)
}

func resolveNetworkUser(name string) (uint32, uint32, string, error) {
	if name == "" || name == "root" {
		return 0, 0, "", errors.New("network user must be a canonical non-root account")
	}
	account, err := user.Lookup(name)
	if err != nil {
		return 0, 0, "", fmt.Errorf("resolve network user: %w", err)
	}
	if account.Username != name {
		return 0, 0, "", errors.New("network user is not the canonical account name")
	}
	uid, err := parseFrozenID(account.Uid)
	if err != nil || uid == 0 {
		return 0, 0, "", errors.New("network user must resolve to a nonzero uid")
	}
	gid, err := parseFrozenID(account.Gid)
	if err != nil {
		return 0, 0, "", errors.New("network user group is not a stable numeric id")
	}
	return uid, gid, account.Username, nil
}

func parseFrozenID(text string) (uint32, error) {
	value, err := strconv.ParseUint(text, 10, 32)
	if err != nil || strconv.FormatUint(value, 10) != text {
		return 0, errors.New("non-canonical numeric id")
	}
	return uint32(value), nil
}
