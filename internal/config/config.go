// SPDX-License-Identifier: Apache-2.0

// Package config loads the protobuf configuration contract and resolves local
// resources. Schema validation is deterministic; resource checks happen here.
package config

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"syscall"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/encoding/protojson"

	configv1 "lindm/gen/lindm/config/v1"
	"lindm/internal/permissionupgrade"
)

const maxFileBytes = 1 << 20

// Document holds the validated contract and its reference directory. Resource
// resolution is explicit so a migration process need not read device signing keys.
type Document struct {
	Proto                              *configv1.ServerConfig
	base                               string
	databaseURLCredential              *systemdCredential
	integrationEncryptionKeyCredential *systemdCredential
}

// Load decodes and validates configuration before accessing referenced resources.
// Relative references resolve against the configuration directory, not the process
// working directory. Files must belong to root or the effective service user.
func Load(path string) (*Document, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve configuration path: %w", err)
	}
	data, err := readFile(absolute, false)
	if err != nil {
		return nil, fmt.Errorf("read configuration: %w", err)
	}
	cfg := new(configv1.ServerConfig)
	if err := (protojson.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("decode configuration: %w", err)
	}
	if lists := upgradeRetiredPermissions(cfg); len(lists) != 0 {
		slog.Warn("configuration names retired permissions; using their current equivalents, update the file", "lists", lists)
	}
	validator, err := protovalidate.New(protovalidate.WithMessages(cfg))
	if err != nil {
		return nil, fmt.Errorf("compile configuration validation rules: %w", err)
	}
	if err := validator.Validate(cfg); err != nil {
		return nil, fmt.Errorf("validate configuration: %w", err)
	}
	return &Document{Proto: cfg, base: filepath.Dir(absolute)}, nil
}

// upgradeRetiredPermissions replaces permission names an earlier release
// accepted, so an unchanged configuration file keeps starting the server.
func upgradeRetiredPermissions(cfg *configv1.ServerConfig) []string {
	var lists []string
	for _, change := range permissionupgrade.Policy(cfg.GetAuthorization()) {
		lists = append(lists, "authorization."+change.List)
	}
	if breakGlass := cfg.GetBreakGlass(); breakGlass != nil {
		upgraded, legacy := permissionupgrade.Permissions(breakGlass.GetAllowedPermissions())
		if len(legacy) != 0 {
			breakGlass.AllowedPermissions = upgraded
			lists = append(lists, "break_glass.allowed_permissions")
		}
	}
	return lists
}

func reference(base, path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(base, path)
}

// readFile checks the opened descriptor, avoiding a separate stat/read race.
// Symlinks are permitted for atomic secret-volume updates; the target must meet
// the same ownership, type and permission requirements as a regular reference.
func readFile(path string, secret bool) (_ []byte, err error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("configuration resources must be regular files")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || (stat.Uid != 0 && stat.Uid != uint32(os.Geteuid())) {
		return nil, errors.New("configuration resources must belong to root or the service user")
	}
	if info.Mode().Perm()&0022 != 0 {
		return nil, errors.New("configuration resources must not be group- or world-writable")
	}
	if secret && info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("secret files must not be accessible to group or other users")
	}
	if info.Size() > maxFileBytes {
		return nil, errors.New("configuration resource exceeds 1 MiB")
	}
	data, err := io.ReadAll(io.LimitReader(f, maxFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxFileBytes {
		return nil, errors.New("configuration resource exceeds 1 MiB")
	}
	return data, nil
}
