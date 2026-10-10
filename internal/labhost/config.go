// Package labhost owns lab host configuration, capacity selection, process-held
// leases and maintained local/SSH host preparation and dispatch. Guest scenario
// implementations and their lifecycle assertions belong to the VM lab.
package labhost

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/encoding/protojson"

	labv1 "lindm/gen/lindm/lab/v1"
)

const maxConfigBytes = 1 << 20

// Load uses LINDM_LAB_CONFIG, then ~/.config/lindm/lab.json, then native local
// defaults. An explicitly configured missing file is an error, not a fallback.
func Load() (*labv1.LabConfig, error) {
	if filename := os.Getenv("LINDM_LAB_CONFIG"); filename != "" {
		return LoadFile(filename)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("lab hosts: locate home directory: %w", err)
	}
	filename := filepath.Join(home, ".config", "lindm", "lab.json")
	cfg, err := LoadFile(filename)
	if errors.Is(err, os.ErrNotExist) {
		return localDefault()
	}
	return cfg, err
}

// LoadFile strictly decodes and validates a bounded, regular protobuf JSON file.
// Remote ~/ paths remain literal until ResolveWorkDirectory runs on that host.
func LoadFile(filename string) (_ *labv1.LabConfig, err error) {
	file, err := os.OpenFile(filename, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("lab hosts: open config: %w", err)
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("lab hosts: stat config: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() > maxConfigBytes {
		return nil, errors.New("lab hosts: config must be a regular file at most 1 MiB")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxConfigBytes+1))
	if err != nil {
		return nil, fmt.Errorf("lab hosts: read config: %w", err)
	}
	if len(data) > maxConfigBytes {
		return nil, errors.New("lab hosts: config exceeds 1 MiB")
	}
	cfg := new(labv1.LabConfig)
	if err := (protojson.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("lab hosts: decode config: %w", err)
	}
	if err := Validate(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

// Validate compiles and applies the protobuf's authoritative declarative rules.
func Validate(cfg *labv1.LabConfig) error {
	if cfg == nil {
		return errors.New("lab hosts: configuration is required")
	}
	validator, err := protovalidate.New(protovalidate.WithMessages(new(labv1.LabConfig)))
	if err != nil {
		return fmt.Errorf("lab hosts: compile configuration rules: %w", err)
	}
	if err := validator.Validate(cfg); err != nil {
		return fmt.Errorf("lab hosts: validate configuration: %w", err)
	}
	return nil
}

// ResolveWorkDirectory resolves a configured host path on the executing machine.
// Call it remotely for an SSH host, never on the orchestration machine. No shell
// evaluation, environment interpolation or named-user tilde expansion occurs.
func ResolveWorkDirectory(host *labv1.LabHost) (string, error) {
	if err := Validate(&labv1.LabConfig{Hosts: []*labv1.LabHost{host}}); err != nil {
		return "", err
	}
	directory := host.WorkDirectory
	if strings.HasPrefix(directory, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("lab hosts: resolve work directory: %w", err)
		}
		directory = filepath.Join(home, strings.TrimPrefix(directory, "~/"))
	}
	return filepath.Abs(directory)
}
