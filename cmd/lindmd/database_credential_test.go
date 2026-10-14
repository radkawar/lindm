// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func credentialCLIConfig(t *testing.T) string {
	t.Helper()
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		if strings.HasPrefix(name, "PG") {
			t.Setenv(name, "")
		}
	}
	dir := t.TempDir()
	config := `{
		"deploymentId":"a9dff5b8-966d-4bbd-a568-b613bc0d056e",
		"publicUrl":"https://localhost:18444",
		"adminListener":{"address":"127.0.0.1","port":18444},
		"deviceListener":{"address":"127.0.0.1","port":18445},
		"database":{"urlFile":"database-url","migrationUrlFile":"database-url","maxConnections":2},
		"tls":{"certificateFile":"server.crt","privateKeyFile":"server.key"},
		"deviceCa":{"certificateFile":"device.crt","privateKeyFile":"device.key"},
		"authentication":{"local":{}}
	}`
	path := filepath.Join(dir, "server.json")
	if err := os.WriteFile(path, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "database-url"), []byte("persistent-secret-canary"), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCLIExplicitDatabaseCredentialFailsClosed(t *testing.T) {
	for _, command := range []string{"serve", "migrate", "check-config", "setup-code"} {
		for _, failure := range []string{"missing directory", "missing file", "empty name", "path instead of name", "unsafe mode", "malformed URL"} {
			t.Run(command+"/"+failure, func(t *testing.T) {
				path := credentialCLIConfig(t)
				dir := t.TempDir()
				if err := os.Chmod(dir, 0700); err != nil {
					t.Fatal(err)
				}
				name := "database-url"
				want := "read database credential"
				switch failure {
				case "missing directory":
					dir = ""
					want = "CREDENTIALS_DIRECTORY"
				case "empty name":
					name = ""
					want = "valid credential name"
				case "path instead of name":
					name = "/etc/lindm/database-url"
					want = "valid credential name"
				case "unsafe mode", "malformed URL":
					mode := os.FileMode(0400)
					if failure == "unsafe mode" {
						mode = 0644
					} else {
						want = "database credential must be a PostgreSQL URL"
					}
					if err := os.WriteFile(filepath.Join(dir, name), []byte("ephemeral-secret-canary"), mode); err != nil {
						t.Fatal(err)
					}
				}
				t.Setenv("CREDENTIALS_DIRECTORY", dir)
				args := []string{command, "-config", path, "-database-url-credential=" + name}
				output := filepath.Join(t.TempDir(), "setup-code")
				if command == "setup-code" {
					args = append(args, "-output", output)
				}
				err := run(context.Background(), args)
				if err == nil || !strings.Contains(err.Error(), want) || strings.Contains(err.Error(), "secret-canary") {
					t.Fatalf("explicit credential failure was not closed/redacted: %v", err)
				}
				if _, err := os.Stat(output); !os.IsNotExist(err) {
					t.Fatal("unsafe credential created setup output")
				}
			})
		}
	}
}

func TestCLIOnlyExplicitFlagSelectsCredential(t *testing.T) {
	path := credentialCLIConfig(t)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "database-url"), []byte("postgresql://runtime@localhost/lindm?sslmode=verify-full"), 0400); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CREDENTIALS_DIRECTORY", dir)
	if err := run(context.Background(), []string{"check-config", "-config", path}); err == nil || !strings.Contains(err.Error(), "database credential must be a PostgreSQL URL") {
		t.Fatalf("environment silently selected an ephemeral credential: %v", err)
	}
	// The real parser and checked loader select the valid credential only when
	// requested, then continue to the unrelated (absent) server TLS resource.
	if err := run(context.Background(), []string{"check-config", "-config", path, "-database-url-credential", "database-url"}); err == nil || !strings.Contains(err.Error(), "load tls certificate") {
		t.Fatalf("explicit credential did not reach normal config resolution: %v", err)
	}
}

func TestCLIRejectsCredentialFlagForOtherCommands(t *testing.T) {
	for _, command := range []string{"bootstrap-owner", "schema-check", "backup", "restore", "custody-status"} {
		t.Run(command, func(t *testing.T) {
			err := run(context.Background(), []string{command, "-database-url-credential", "database-url"})
			want := "flag provided but not defined"
			if command == "backup" || command == "restore" || command == "custody-status" {
				want = "operations: invalid_arguments"
			}
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("unrelated command accepted database credential flag: %v", err)
			}
		})
	}
}
