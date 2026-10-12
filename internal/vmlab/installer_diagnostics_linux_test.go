//go:build linux

package vmlab

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallerFailureDiagnosticsBoundRedactAndPreserveCause(t *testing.T) {
	dir := t.TempDir()
	private, public, err := encryptedKey()
	if err != nil {
		t.Fatal(err)
	}
	d := newInstallerDiagnostics(dir, installerFailureSnapshot, "aarch64", strings.Repeat("a", 64), string(private), public)
	for _, piece := range []string{"Linux version test\nLINDM_INSTALLER_STA", "GE=profile-pre\r\n", strings.Repeat("bounded installer output\n", 4096), string(private), public, base64.StdEncoding.EncodeToString(private), "\nNo installation repository found\n"} {
		if _, err := d.Write([]byte(piece)); err != nil {
			t.Fatal(err)
		}
	}
	process := &encryptedProcess{log: new(vmLog)}
	if _, err := process.log.Write([]byte("QEMU diagnostic in " + dir)); err != nil {
		t.Fatal(err)
	}
	failure := d.saveFailure(dir, process, context.DeadlineExceeded)
	if !errors.Is(failure, context.DeadlineExceeded) {
		t.Fatal("installer failure lost the original deadline cause")
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("private diagnostics not saved: %v, %v", entries, err)
	}
	path := filepath.Join(dir, entries[0].Name())
	if !strings.Contains(failure.Error(), path) {
		t.Fatal("installer error did not identify retained diagnostics")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("diagnostic permissions = %v", info.Mode())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) > 256<<10 || strings.Contains(string(data), dir) {
		t.Fatal("diagnostic escaped its bound or exposed the private run path")
	}
	var evidence struct {
		Kind         string                      `json:"kind"`
		SourceSHA256 string                      `json:"source_sha256"`
		SerialTail   string                      `json:"serial_tail_redacted"`
		QEMUStderr   string                      `json:"qemu_stderr"`
		Truncated    bool                        `json:"serial_truncated"`
		Stages       []installerStageObservation `json:"observed_stages"`
	}
	if err := json.Unmarshal(data, &evidence); err != nil {
		t.Fatal(err)
	}
	if evidence.Kind != installerFailureSnapshot || evidence.SourceSHA256 != strings.Repeat("a", 64) || !evidence.Truncated || len(evidence.Stages) != 2 || evidence.Stages[1].Stage != "profile-pre" {
		t.Fatalf("lost immutable source or fragmented stage observations: %+v", evidence)
	}
	if !strings.Contains(evidence.SerialTail, "No installation repository found") || !strings.Contains(evidence.QEMUStderr, "QEMU diagnostic") {
		t.Fatal("failure lost separate serial and emulator diagnostics")
	}
	for _, secret := range append(strings.Fields(string(private)), strings.Fields(public)...) {
		if len(secret) >= 16 && strings.Contains(string(data), secret) {
			t.Fatal("diagnostic retained a credential fragment")
		}
	}
	if strings.Contains(string(data), base64.StdEncoding.EncodeToString(private)) {
		t.Fatal("diagnostic retained encoded credential")
	}
}

func TestInstallerStageRequiresObservedMarkerNotPrintedRecipe(t *testing.T) {
	d := newInstallerDiagnostics(t.TempDir(), installerFailureOffline, "aarch64", strings.Repeat("a", 64))
	if _, err := d.Write([]byte("printf '%s\\n' 'LINDM_INSTALLER_STAGE=provision-complete' > /dev/console\n")); err != nil {
		t.Fatal(err)
	}
	if len(d.stages) != 0 {
		t.Fatal("printed recipe falsely claimed execution of a provisioning stage")
	}
	if _, err := d.Write([]byte("LINDM_INSTALLER_STAGE=provision-complete\n")); err != nil {
		t.Fatal(err)
	}
	if len(d.stages) != 1 || d.stages[0].Stage != "provision-complete" {
		t.Fatal("actual provisioning marker was not observed")
	}
}

func TestInstallerCursesTailSurvivesWithoutLineFeeds(t *testing.T) {
	for _, boundary := range []string{"\r", "\x1b[10;1H"} {
		t.Run(fmt.Sprintf("%q", boundary), func(t *testing.T) {
			dir := t.TempDir()
			d := newInstallerDiagnostics(dir, installerFailureOffline, "aarch64", strings.Repeat("a", 64))
			output := strings.Repeat("x", installerSerialLimit+1) + boundary + "AutoYaST: No installation source found" + boundary + "Retry Abort"
			if _, err := d.Write([]byte(output)); err != nil {
				t.Fatal(err)
			}
			failure := d.saveFailure(dir, nil, context.Canceled)
			if !errors.Is(failure, context.Canceled) {
				t.Fatal("diagnostic changed cancellation cause")
			}
			entries, err := os.ReadDir(dir)
			if err != nil || len(entries) != 1 {
				t.Fatalf("private diagnostic not saved: %v", err)
			}
			data, err := os.ReadFile(filepath.Join(dir, entries[0].Name()))
			if err != nil {
				t.Fatal(err)
			}
			var evidence struct {
				SerialTail string `json:"serial_tail_redacted"`
			}
			if err := json.Unmarshal(data, &evidence); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(evidence.SerialTail, "No installation source found") || !strings.Contains(evidence.SerialTail, "Retry Abort") || strings.Contains(evidence.SerialTail, "xxxxxxxx") {
				t.Fatal("curses tail lost safe dialog text or retained the partial opaque prefix")
			}
		})
	}
}
