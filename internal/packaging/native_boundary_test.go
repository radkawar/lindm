//go:build linux

package packaging

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func requireNativeTools(t *testing.T, names ...string) {
	t.Helper()
	for _, name := range names {
		if _, err := defaultLookupTool(name); err != nil {
			t.Fatalf("native regression requires %s: %v", name, err)
		}
	}
}

func TestToolStreamsLargeArtifact(t *testing.T) {
	requireNativeTools(t, "cat")
	work := t.TempDir()
	data := bytes.Repeat([]byte("payload\x00"), toolOutputLimit/8+1)
	path := filepath.Join(work, "artifact")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	var artifact bytes.Buffer
	captured, _, err := runTool(context.Background(), work, toolCmd{Name: "cat", Args: []string{path}, Stdout: &artifact})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(artifact.Bytes(), data) || len(captured) != 0 {
		t.Fatalf("streamed %d bytes, captured %d; want %d streamed only", artifact.Len(), len(captured), len(data))
	}
	if _, _, err := runTool(context.Background(), work, toolCmd{Name: "cat", Args: []string{path}}); !errors.Is(err, ErrArtifact) {
		t.Fatalf("unbounded diagnostic capture accepted: %v", err)
	}
}

func TestRPMPayloadPathIsLiteral(t *testing.T) {
	requireNativeTools(t, "rpmbuild", "rpm2cpio", "cpio")
	work := t.TempDir()
	// Both shell expansion and RPM macro expansion must remain literal data.
	payload := filepath.Join(work, "payload ' $(touch SHELL_EXPANDED) %{_arch}")
	for _, dir := range []string{"usr/libexec/lindm", "etc/lindm", "usr/share/doc/lindm-agent"} {
		if err := os.MkdirAll(filepath.Join(payload, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	rel := BinaryPath[1:]
	data := []byte("literal payload\n")
	if err := os.WriteFile(filepath.Join(payload, rel), data, 0o755); err != nil {
		t.Fatal(err)
	}
	spec, err := writeSpec(work, payload, "0.2.0", Architecture{RPM: "x86_64"}, DefaultSourceDateEpoch, []stagedFile{{Rel: rel, Mode: 0o755}}, agentProduct())
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = runTool(context.Background(), work, toolCmd{Name: "rpmbuild", Args: []string{"-bb", spec, "--define", "_topdir " + filepath.Join(work, "rpm"), "--define", "__os_install_post /bin/true", "--define", "debug_package %{nil}"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(work, "SHELL_EXPANDED")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("shell expansion executed: %v", err)
	}
	rpm, err := findOne(filepath.Join(work, "rpm"), ".rpm")
	if err != nil {
		t.Fatal(err)
	}
	extract := filepath.Join(work, "extract")
	if err := os.Mkdir(extract, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := pipeTools(context.Background(), work, toolCmd{Name: "rpm2cpio", Args: []string{rpm}}, toolCmd{Name: "cpio", Args: []string{"--extract", "--make-directories", "--quiet", "--no-absolute-filenames", "-D", extract}, Dir: extract}); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(extract, rel))
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("literal payload not preserved: %q, %v", got, err)
	}
}

func TestCanceledSigningAgentCleanup(t *testing.T) {
	requireNativeTools(t, "gpgconf", "gpg-connect-agent")
	work := t.TempDir()
	home := filepath.Join(work, "gnupg")
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := stopAgent(context.Background(), work, home); err != nil {
			t.Errorf("test signing-agent teardown: %v", err)
		}
	}()
	if _, _, err := runTool(context.Background(), work, toolCmd{Name: "gpg-connect-agent", Args: []string{"--homedir", home, "/bye"}}); err != nil {
		t.Fatal(err)
	}
	socketOutput, _, err := runTool(context.Background(), work, toolCmd{Name: "gpgconf", Args: []string{"--homedir", home, "--list-dirs", "agent-socket"}})
	if err != nil {
		t.Fatal(err)
	}
	socket := strings.TrimSpace(string(socketOutput))
	conn, err := net.DialTimeout("unix", socket, time.Second)
	if err != nil {
		t.Fatalf("agent was not initially reachable: %v", err)
	}
	_ = conn.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := stopAgent(ctx, work, home); err != nil {
		t.Fatal(err)
	}
	// gpg-connect-agent can exit successfully after an Assuan ERR response.
	// Probe the actual socket instead of treating its exit status as liveness.
	deadline := time.Now().Add(3 * time.Second)
	for {
		conn, err := net.DialTimeout("unix", socket, time.Second)
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ECONNREFUSED) {
			break
		}
		if err != nil {
			t.Fatalf("checking agent liveness: %v", err)
		}
		_ = conn.Close()
		if time.Now().After(deadline) {
			t.Fatal("signing agent remains reachable after canceled cleanup")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
