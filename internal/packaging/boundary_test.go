// SPDX-License-Identifier: Apache-2.0

//go:build linux

package packaging

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestBuildRejectsUnsafeBinary(t *testing.T) {
	_, err := Build(context.Background(), BuildRequest{
		AgentBinary: "lindm-agent",
		Version:     "0.2.0",
		OutputDir:   t.TempDir(),
	})
	if !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("relative binary: %v", err)
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "agent")
	if err := os.WriteFile(target, []byte("not an elf"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "linked")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	_, err = Build(context.Background(), BuildRequest{
		AgentBinary: link,
		Version:     "0.2.0",
		OutputDir:   dir,
	})
	if !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("symlink binary: %v", err)
	}
}

func TestUpgradeOrdered(t *testing.T) {
	if err := UpgradeOrdered("0.2.0", "0.2.1"); err != nil {
		t.Fatal(err)
	}
	if err := UpgradeOrdered("0.2.0", "0.2.0"); !errors.Is(err, ErrVersion) {
		t.Fatalf("equal: %v", err)
	}
	if err := UpgradeOrdered("0.2.1", "0.2.0"); !errors.Is(err, ErrVersion) {
		t.Fatalf("downgrade: %v", err)
	}
	if err := UpgradeOrdered("0.2", "0.3.0"); !errors.Is(err, ErrVersion) {
		t.Fatalf("short version: %v", err)
	}
	if err := UpgradeOrdered("1.0.0", "1.0.10"); err != nil {
		t.Fatal(err)
	}
}

func TestInspectELF(t *testing.T) {
	script := filepath.Join(t.TempDir(), "script")
	if err := os.WriteFile(script, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(script)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	if _, err := inspectELF(file); !errors.Is(err, ErrArchitecture) {
		t.Fatalf("script: %v", err)
	}
	elfPath := filepath.Join(t.TempDir(), "elf")
	if err := os.WriteFile(elfPath, minimalELF(elfEM386), 0o755); err != nil {
		t.Fatal(err)
	}
	wrong, err := os.Open(elfPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = wrong.Close() }()
	if _, err := inspectELF(wrong); !errors.Is(err, ErrArchitecture) {
		t.Fatalf("wrong machine: %v", err)
	}
	okPath := filepath.Join(t.TempDir(), "amd64")
	if err := os.WriteFile(okPath, minimalELF(62), 0o755); err != nil {
		t.Fatal(err)
	}
	ok, err := os.Open(okPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ok.Close() }()
	arch, err := inspectELF(ok)
	if err != nil {
		t.Fatal(err)
	}
	if arch.Debian != "amd64" || arch.RPM != "x86_64" || arch.GOARCH != "amd64" {
		t.Fatalf("arch: %+v", arch)
	}
}

func TestPublishRPMDoesNotInventRepodata(t *testing.T) {
	previous := lookupTool
	t.Cleanup(func() { lookupTool = previous })
	lookupTool = func(name string) (string, error) {
		if name == "createrepo_c" {
			return "", fmt.Errorf("%w: createrepo_c", ErrToolMissing)
		}
		return "/usr/bin/" + name, nil
	}
	dir := t.TempDir()
	_, err := PublishRPM(context.Background(), RPMRequest{
		OutputDir: dir,
		RPMs:      []string{"/tmp/lindm-agent-0.2.0-1.x86_64.rpm"},
	})
	if !errors.Is(err, ErrRepositoryTool) {
		t.Fatalf("missing createrepo_c: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("repository tool absence wrote %d entries", len(entries))
	}
}

func TestRepositoryRejectsUnsafePaths(t *testing.T) {
	if _, err := APTSources("/srv/lindm", "/etc/apt/trusted.gpg"); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("trusted.gpg: %v", err)
	}
	if _, err := APTSources("/srv/lindm", "/etc/apt/trusted.gpg.d/lindm.gpg"); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("trusted.gpg.d: %v", err)
	}
	if _, err := APTSources("repo", "/etc/apt/keyrings/lindm.gpg"); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("relative repo: %v", err)
	}
}

func TestUnitVerifyAllowsMissingPackagedBinary(t *testing.T) {
	missing, err := classifyUnitOutput("lindm-executor.service: Command " + BinaryPath + " is not executable: No such file or directory\n")
	if err != nil || !missing {
		t.Fatalf("missing binary: %v %v", missing, err)
	}
	if _, err := classifyUnitOutput("lindm-executor.service: Unknown key name 'Nope'"); err == nil {
		t.Fatal("unexpected unit diagnostic was accepted")
	}
}

func TestPassphraseRejectsRPMMacros(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"passphrase", "%{lua:print('unexpected')}"} {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte("protected"), 0o600); err != nil {
			t.Fatal(err)
		}
		err := checkPassphrase(path)
		if name == "passphrase" && err != nil {
			t.Fatalf("safe passphrase path: %v", err)
		}
		if name != "passphrase" && !errors.Is(err, ErrUnsafePath) {
			t.Fatalf("macro-bearing passphrase path accepted: %v", err)
		}
	}
}

const elfEM386 = 3

func minimalELF(machine uint16) []byte {
	buf := make([]byte, 64)
	copy(buf, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	buf[16] = 3 // ET_DYN
	buf[18] = byte(machine)
	buf[19] = byte(machine >> 8)
	buf[20] = 1 // version
	buf[52] = 64
	buf[54] = 56
	buf[58] = 64
	return buf
}
