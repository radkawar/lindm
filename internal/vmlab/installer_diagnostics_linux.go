//go:build linux

package vmlab

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"lindm/internal/agent/nativeexec"
)

const installerSerialLimit = 64 << 10

type installerStageObservation struct {
	Stage string    `json:"stage"`
	At    time.Time `json:"at"`
}

// Only the offline unencrypted bootstrap may enable console diagnostics.
// Serial bytes stay in bounded memory until failure; credentials and opaque
// encoded payloads are removed before writing the owner-only diagnostic file.
// Stage observations survive tail truncation and are observations, not success.
type installerDiagnostics struct {
	mu           sync.Mutex
	directory    string
	architecture string
	sourceDigest string
	started      time.Time
	tail         *nativeexec.Buffer
	total        int64
	line         []byte
	stages       []installerStageObservation
	secrets      []string
}

func newInstallerDiagnostics(directory, architecture, sourceDigest string, secrets ...string) *installerDiagnostics {
	if directory == "" {
		directory = os.TempDir()
	}
	d := &installerDiagnostics{directory: directory, architecture: architecture, sourceDigest: sourceDigest, started: time.Now().UTC(), tail: nativeexec.NewTailBuffer(installerSerialLimit)}
	for _, secret := range secrets {
		if secret == "" {
			continue
		}
		d.secrets = append(d.secrets, secret, base64.StdEncoding.EncodeToString([]byte(secret)))
		// PEM bodies and recipe payloads may be displayed one wrapped line
		// at a time rather than as the complete input string.
		for _, token := range strings.FieldsFunc(secret, func(r rune) bool { return r == '\n' || r == '\r' || r == '\'' }) {
			if len(token) >= 16 {
				d.secrets = append(d.secrets, token)
			}
		}
	}
	return d
}

func (d *installerDiagnostics) Write(p []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.total += int64(len(p))
	for _, b := range p {
		if b == '\n' || b == '\r' {
			d.observeLine()
			d.line = d.line[:0]
		} else if len(d.line) < 4096 {
			d.line = append(d.line, b)
		}
	}
	return d.tail.Write(p)
}

func (d *installerDiagnostics) observeLine() {
	for _, marker := range []struct{ text, stage string }{
		{"UEFI Interactive Shell", "uefi-shell"},
		{"Linux version ", "linux-kernel"},
		{"linuxrc", "linuxrc"},
		{"LINDM_INSTALLER_STAGE=profile-pre", "profile-pre"},
		{"LINDM_INSTALLER_STAGE=provision-start", "provision-start"},
		{"LINDM_INSTALLER_STAGE=provision-complete", "provision-complete"},
	} {
		matched := bytes.Contains(d.line, []byte(marker.text))
		if strings.HasPrefix(marker.text, "LINDM_INSTALLER_STAGE=") {
			matched = bytes.Equal(bytes.TrimSpace(d.line), []byte(marker.text))
		}
		if !matched {
			continue
		}
		found := false
		for _, observed := range d.stages {
			found = found || observed.Stage == marker.stage
		}
		if !found {
			d.stages = append(d.stages, installerStageObservation{Stage: marker.stage, At: time.Now().UTC()})
		}
	}
}

func (d *installerDiagnostics) redact(text, dir string) string {
	// Curses dialogs use cursor-addressing and carriage returns instead of
	// newline-delimited output. Keep those text boundaries rather than
	// concatenating unrelated screen cells (or dropping the entire screen).
	text = strings.ReplaceAll(text, "\r", "\n")
	text = regexp.MustCompile(`\x1b\[[0-?]*[ -/]*[@-~]`).ReplaceAllString(text, "\n")
	for _, secret := range d.secrets {
		text = strings.ReplaceAll(text, secret, "<credential-redacted>")
	}
	// In addition to exact inputs, suppress PEM blocks and encoded fragments
	// split by terminal wrapping. The first truncated line is discarded below.
	text = regexp.MustCompile(`(?s)-----BEGIN [^-]*PRIVATE KEY-----.*?(-----END [^-]*PRIVATE KEY-----|$)`).ReplaceAllString(text, "<private-key-redacted>")
	text = regexp.MustCompile(`(?m)^[ \t]*[A-Za-z0-9+/=]{16,}[ \t]*$`).ReplaceAllString(text, "<encoded-line-redacted>")
	text = regexp.MustCompile(`[A-Za-z0-9+/=_-]{32,}`).ReplaceAllString(text, "<opaque-token-redacted>")
	text = strings.ReplaceAll(text, dir, "<private-run>")
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' || r >= 32 && r <= 126 {
			return r
		}
		return ' '
	}, text)
}

func (d *installerDiagnostics) saveFailure(dir string, process *encryptedProcess, cause error) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.observeLine()
	serial := d.tail.String()
	if d.total > installerSerialLimit {
		// Discard only the initial incomplete terminal span. Native YaST
		// can emit an entire 64 KiB curses tail without any LF; a cursor
		// control or CR still gives a fresh, independently redacted span.
		if cut := strings.IndexAny(serial, "\n\r\x1b"); cut >= 0 {
			serial = serial[cut:]
		} else {
			serial = "<truncated line withheld>"
		}
	}
	stderr := ""
	if process != nil {
		stderr = process.log.diagnostic(dir)
	}
	data, err := json.MarshalIndent(struct {
		Kind         string                      `json:"kind"`
		Architecture string                      `json:"architecture"`
		SourceSHA256 string                      `json:"source_sha256"`
		StartedAt    time.Time                   `json:"started_at"`
		FailedAt     time.Time                   `json:"failed_at"`
		Error        string                      `json:"error"`
		SerialBytes  int64                       `json:"serial_bytes"`
		Truncated    bool                        `json:"serial_truncated"`
		SerialTail   string                      `json:"serial_tail_redacted"`
		QEMUStderr   string                      `json:"qemu_stderr"`
		Stages       []installerStageObservation `json:"observed_stages"`
	}{"offline-dvd-installer-failure", d.architecture, d.sourceDigest, d.started, time.Now().UTC(), d.redact(cause.Error(), dir), d.total, d.total > installerSerialLimit, d.redact(serial, dir), d.redact(stderr, dir), d.stages}, "", "  ")
	if err != nil {
		return errors.Join(cause, fmt.Errorf("encode private installer diagnostics: %w", err))
	}
	saved, err := saveGuestDiagnostics(d.directory, data)
	if err != nil {
		return errors.Join(cause, err)
	}
	return fmt.Errorf("%w; private installer diagnostics %s", cause, saved)
}
