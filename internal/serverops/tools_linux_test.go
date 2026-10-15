// SPDX-License-Identifier: Apache-2.0

package serverops

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestToolFailureRetainsSafeContextCause(t *testing.T) {
	for _, deadline := range []bool{false, true} {
		t.Run(map[bool]string{false: "cancelled", true: "deadline"}[deadline], func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			cause := context.Canceled
			if deadline {
				cancel()
				ctx, cancel = context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
				cause = context.DeadlineExceeded
			} else {
				cancel()
			}
			defer cancel()
			err := runTool(ctx, "/bin/sh", []string{"-c", "printf test-private-password >&2"}, cleanEnvironment(), nil, io.Discard)
			if !errors.Is(err, cause) || !strings.HasPrefix(err.Error(), "operations: sh_failed:") || strings.Contains(err.Error(), "test-private-password") {
				t.Fatalf("safe cancellation classification lost: %v", err)
			}
		})
	}
}

func TestToolFailureRedactsStderrAndArguments(t *testing.T) {
	var output bytes.Buffer
	err := runTool(t.Context(), "/bin/sh", []string{"-c", "printf test-private-password >&2; exit 2"}, cleanEnvironment(), nil, &output)
	if err == nil || err.Error() != "operations: sh_failed" || output.Len() != 0 {
		t.Fatal("subprocess failure exposed private stderr or arguments")
	}
}

func TestToolPrivateDiagnosticUsesSameRedactedRunner(t *testing.T) {
	var output, diagnostic bytes.Buffer
	err := runToolWithStderr(t.Context(), "/bin/sh", []string{"-c", "printf test-private-password >&2; exit 2"}, cleanEnvironment(), nil, &output, &diagnostic)
	if err == nil || err.Error() != "operations: sh_failed" || output.Len() != 0 || diagnostic.String() != "test-private-password" {
		t.Fatal("explicit diagnostic sink changed public failure redaction")
	}
}

func TestPostgreSQLToolVersionRequiresExactSupportedMajor(t *testing.T) {
	for _, tool := range []string{"pg_dump", "pg_restore"} {
		for _, selected := range []int{0, 14, 15, 16, 17, 18, 19} {
			for _, actual := range []int{14, 15, 16, 17, 18, 19} {
				version := fmt.Sprintf("%s (PostgreSQL) %d.2 (Debian fixture)\n", tool, actual)
				err := checkPostgreSQLToolVersion(tool, version, selected)
				want := selected >= 16 && selected <= 18 && selected == actual
				if (err == nil) != want {
					t.Fatalf("tool=%s selected=%d actual=%d: %v", tool, selected, actual, err)
				}
			}
			for _, version := range []string{"", tool + " 16.1", "postgres (PostgreSQL) 16.1", tool + " (PostgreSQL) invalid"} {
				if err := checkPostgreSQLToolVersion(tool, version, selected); err == nil {
					t.Fatalf("malformed or wrong executable admitted: %q", version)
				}
			}
		}
	}
}

func TestDatabaseArchiveMajorRequiresMatchingSupportedDumpAndServer(t *testing.T) {
	for _, server := range []int{14, 15, 16, 17, 18, 19} {
		for _, dump := range []int{14, 15, 16, 17, 18, 19} {
			listing := fmt.Sprintf(";\n; Archive created at fixture\n;     Dumped from database version: %d.9 (vendor)\n;     Dumped by pg_dump version: %d.1\n;\n", server, dump)
			major, err := archivePostgreSQLMajor(listing)
			want := server >= 16 && server <= 18 && server == dump
			if (err == nil) != want || (want && major != server) {
				t.Fatalf("server=%d dump=%d: major=%d error=%v", server, dump, major, err)
			}
		}
	}
	for _, listing := range []string{
		"",
		"; Dumped from database version: 16.2\n",
		"; Dumped by pg_dump version: 16.2\n",
		"; Dumped from database version: invalid\n; Dumped by pg_dump version: 16.2\n",
		"; Dumped from database version: invalid\n; Dumped from database version: 16.2\n; Dumped by pg_dump version: 16.2\n",
		"; Dumped from database version: 16.2\n; Dumped by pg_dump version: 16.2\n; Dumped by pg_dump version: 16.2\n",
	} {
		if _, err := archivePostgreSQLMajor(listing); err == nil {
			t.Fatalf("malformed archive version header admitted: %q", listing)
		}
	}
}

func TestArchiveHeaderWriterBoundsOnlyCaptureNotParserOutput(t *testing.T) {
	var output archiveHeaderWriter
	for _, input := range []string{"; fixture\n", strings.Repeat("x", 8192), "tail"} {
		n, err := output.Write([]byte(input))
		if err != nil || n != len(input) {
			t.Fatalf("archive parser output was truncated: n=%d error=%v", n, err)
		}
	}
	if len(output.header) != 4096 || !strings.HasPrefix(string(output.header), "; fixture\n") {
		t.Fatal("unbounded or incorrect archive header capture")
	}
}

func writePostgreSQLToolFixture(t *testing.T, directory, tool, body string) string {
	t.Helper()
	path := filepath.Join(directory, tool)
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body+"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestDatabaseArchiveCheckIsOfflineAndUsesExactRestoreClient(t *testing.T) {
	for _, client := range []int{15, 16, 17, 18, 19} {
		for _, source := range []int{16, 17, 18} {
			t.Run(fmt.Sprintf("client=%d/source=%d", client, source), func(t *testing.T) {
				directory := t.TempDir()
				t.Setenv("PATH", directory)
				// No postgres, pg_dump or live database exists in this fixture.
				body := fmt.Sprintf(`case "$1" in
--version) printf 'pg_restore (PostgreSQL) %d.1\n' ;;
--list) printf ';\n;     Dumped from database version: %d.2\n;     Dumped by pg_dump version: %d.1\n;\n' ;;
*) exit 91 ;;
esac`, client, source, source)
				path := writePostgreSQLToolFixture(t, directory, "pg_restore", body)
				tool, major, err := checkDatabaseArchive(t.Context(), "/offline/database.dump")
				if client != source {
					if err == nil {
						t.Fatal("mismatched restore client accepted")
					}
				} else if err != nil || tool != path || major != source {
					t.Fatalf("offline archive: tool=%q major=%d error=%v", tool, major, err)
				}
			})
		}
	}
}

func TestDumpRejectsMismatchedClientsBeforeCredentialsOrOutput(t *testing.T) {
	for _, wrong := range []string{"pg_dump", "pg_restore"} {
		for _, actual := range []int{15, 17, 18, 19} {
			t.Run(fmt.Sprintf("%s=%d", wrong, actual), func(t *testing.T) {
				directory := t.TempDir()
				t.Setenv("PATH", directory)
				for _, tool := range []string{"pg_dump", "pg_restore"} {
					version := 16
					if tool == wrong {
						version = actual
					}
					body := fmt.Sprintf("[ \"$1\" = --version ] || exit 91\nprintf '%s (PostgreSQL) %d.1\\n'", tool, version)
					writePostgreSQLToolFixture(t, directory, tool, body)
				}
				stage := t.TempDir()
				_, err := dumpDatabase(t.Context(), stage, "invalid-private-connection", 16)
				if err == nil || !strings.Contains(err.Error(), wrong+"_major_mismatch") || strings.Contains(err.Error(), "private") {
					t.Fatalf("client mismatch did not fail closed before credentials: %v", err)
				}
				if entries, err := os.ReadDir(stage); err != nil || len(entries) != 0 {
					t.Fatal("client refusal wrote staging artifacts")
				}
			})
		}
	}
}

func TestDumpUsesMatchingClientsWithoutPostgresAndChecksActualArchive(t *testing.T) {
	for _, selected := range []int{16, 17, 18} {
		for _, source := range []int{15, 16, 17, 18, 19} {
			t.Run(fmt.Sprintf("selected=%d/source=%d", selected, source), func(t *testing.T) {
				directory := t.TempDir()
				t.Setenv("PATH", directory)
				dumpBody := fmt.Sprintf(`case "$1" in
--version) printf 'pg_dump (PostgreSQL) %d.1\n' ;;
--dbname=service=lindm-backup) printf 'custom-dump-fixture' ;;
*) exit 91 ;;
esac`, selected)
				writePostgreSQLToolFixture(t, directory, "pg_dump", dumpBody)
				restoreBody := fmt.Sprintf(`case "$1" in
--version) printf 'pg_restore (PostgreSQL) %d.1\n' ;;
--list) printf ';\n;     Dumped from database version: %d.1\n;     Dumped by pg_dump version: %d.1\n;\n' ;;
*) exit 91 ;;
esac`, selected, source, selected)
				writePostgreSQLToolFixture(t, directory, "pg_restore", restoreBody)
				stage := t.TempDir()
				path, err := dumpDatabase(t.Context(), stage, "postgresql://migrator:fixture@database/lindm?sslmode=verify-full&channel_binding=require&require_auth=scram-sha-256", selected)
				if selected != source {
					if err == nil {
						t.Fatal("dump from actual mismatched database archive accepted")
					}
					return
				}
				if err != nil || path != filepath.Join(stage, "database.dump") {
					t.Fatalf("matching backup without postgres executable: path=%q error=%v", path, err)
				}
				content, err := os.ReadFile(path)
				if err != nil || string(content) != "custom-dump-fixture" {
					t.Fatal("checked dump tool output not preserved")
				}
				service, err := os.ReadFile(filepath.Join(stage, "pg-service.conf"))
				if err != nil || !strings.Contains(string(service), "channel_binding=require\n") ||
					!strings.Contains(string(service), "require_auth=scram-sha-256\n") {
					t.Fatal("tool version admission weakened libpq authentication policy")
				}
			})
		}
	}
}
