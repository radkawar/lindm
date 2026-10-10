package update

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/agent/journal"
)

func failingNativeChild(t *testing.T, stdout, stderr string) error {
	t.Helper()
	quote := func(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'" }
	path := filepath.Join(t.TempDir(), "apt-get")
	script := "#!/bin/sh\nprintf '%s' " + quote(stdout) + "\nprintf '%s' " + quote(stderr) + " >&2\nexit 100\n"
	if err := os.WriteFile(path, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	_, err := nativeCommand(t.Context(), "simulate", path, "--never-log-this-argument")
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 100 {
		t.Fatalf("real child exit was lost: %v", err)
	}
	return err
}

func TestNativeFailureCapturesActualFinalErrorsWithoutRawCause(t *testing.T) {
	err := failingNativeChild(t, "Problem: conflicting requests for lindm-agent\n", "\x1b[31mE: Unsupported file /var/lib/lindm/updates/agent.deb given on commandline\x1b[0m\n")
	diagnostic := diagnosticForError(withNativeDiagnostic(err, "apt-get", "recovery"))
	if diagnostic.GetManager() != "apt-get" || diagnostic.GetPhase() != "simulate" || diagnostic.GetExitCode() != 100 {
		t.Fatalf("failure context changed: %v", diagnostic)
	}
	want := []string{"Problem: conflicting requests for lindm-agent", "E: Unsupported file /var/lib/lindm/updates/agent.deb given on commandline"}
	if strings.Join(diagnostic.GetErrorLines(), "\n") != strings.Join(want, "\n") || diagnostic.GetTruncated() {
		t.Fatalf("actual native errors not preserved: %v", diagnostic)
	}
	for _, forbidden := range []string{"Unsupported", "/var/lib", "never-log", "commandline"} {
		if strings.Contains(err.Error(), forbidden) {
			t.Fatalf("raw output/argv leaked into error: %v", err)
		}
	}
	missing := filepath.Join(t.TempDir(), "private-path-secret", "apt-get")
	_, startErr := nativeCommand(t.Context(), "apply", missing)
	if startErr == nil || strings.Contains(startErr.Error(), "private-path-secret") || diagnosticForError(startErr).GetExitCode() != -1 {
		t.Fatalf("start failure exposed raw exec error or invented exit: %v", startErr)
	}
}

func TestNativeDiagnosticSanitizationAndDeterministicBounds(t *testing.T) {
	for _, test := range []struct{ input, want string }{
		{"E: download https://owner:password@repo.example/secret?key=hidden failed", "[redacted sensitive native output]"},
		{"E: download https://owner:opaque@repo.example/private?opaque failed", "E: download [redacted-url] failed"},
		{"ENV_VALUE='private environment contents'", "[redacted sensitive native output]"},
		{"Authorization: Bearer opaque", "[redacted sensitive native output]"},
		{"password: hidden", "[redacted sensitive native output]"},
		{"\x1b]8;;https://private.invalid/opaque\aE: lindm-agent broken\x1b]8;;\a\x00\u0085\u202e", "E: lindm-agent broken"},
	} {
		line, truncated := sanitizeNativeLine(test.input)
		if line != test.want || truncated {
			t.Fatalf("sanitized line = %q, truncated=%t; want %q", line, truncated, test.want)
		}
	}
	var output strings.Builder
	for i := range 12 {
		output.WriteString(strconv.Itoa(i) + ": " + strings.Repeat("界", 300) + "\n")
	}
	diagnostic := diagnosticForError(failingNativeChild(t, "", output.String()))
	if len(diagnostic.GetErrorLines()) != 8 || !diagnostic.GetTruncated() || !strings.HasPrefix(diagnostic.GetErrorLines()[0], "4: ") || !strings.HasPrefix(diagnostic.GetErrorLines()[7], "11: ") {
		t.Fatalf("not the bounded final eight lines: %v", diagnostic)
	}
	total := 0
	for _, line := range diagnostic.GetErrorLines() {
		total += len(line)
		if len(line) > 512 || !utf8.ValidString(line) || strings.ContainsFunc(line, unicode.IsControl) {
			t.Fatalf("unsafe diagnostic line: %q", line)
		}
	}
	if total > 4096 {
		t.Fatalf("diagnostic exceeds total envelope: %d", total)
	}
}

func TestNativeFailureKeepsFinalErrorAfterOutputOverflow(t *testing.T) {
	diagnostic := diagnosticForError(failingNativeChild(t, "", strings.Repeat("progress\n", 10000)+"E: Unable to locate package lindm-agent\n"))
	if diagnostic.GetExitCode() != 100 || !diagnostic.GetTruncated() || diagnostic.GetErrorLines()[len(diagnostic.GetErrorLines())-1] != "E: Unable to locate package lindm-agent" {
		t.Fatalf("prefix output bound hid final native error: %v", diagnostic)
	}
}

func TestNativeDiagnosticWithholdsPEMBodyAcrossChunksAndTailRotation(t *testing.T) {
	var stdout, stderr commandOutput
	for _, chunk := range []string{"-----BE", "GIN PRIVATE KEY-----\n", strings.Repeat("cHJpdmF0ZS1rZXktbWF0ZXJpYWw=\n", 3000), "-----END PRIVATE KEY-----\n"} {
		if _, err := stderr.Write([]byte(chunk)); err != nil {
			t.Fatal(err)
		}
	}
	diagnostic := commandDiagnostic("apt-get", "apply", verificationExit(100), &stdout, &stderr)
	if strings.Join(diagnostic.GetErrorLines(), "\n") != "[redacted sensitive native output]" || !diagnostic.GetTruncated() {
		t.Fatalf("PEM body survived source sanitization: %v", diagnostic)
	}
}

func TestNativeFailurePersistsThroughHelperJournalRestartAndChecking(t *testing.T) {
	root := protectedRetentionDirectory(t)
	store, err := journal.OpenUpdates(root)
	if err != nil {
		t.Fatal(err)
	}
	tx := retentionFixture(t, store.Directory, "")
	directory := filepath.Join(store.Directory, tx.GetId())
	failure := failingNativeChild(t, "", "E: Failed to fetch admitted local package /var/lib/lindm/agent.deb\n")
	if err := writeHelperState(directory, "recovery_required", nil, failure); err != nil {
		t.Fatal(err)
	}
	helper := &agentv1.AgentUpdateHelperState{}
	if err := journal.ReadUpdateRecord(directory, "helper.pb", helper); err != nil {
		t.Fatal(err)
	}
	want := diagnosticForError(failure)
	if !proto.Equal(helper.GetNativeDiagnostic(), want) {
		t.Fatal("durable copied helper lost failure")
	}
	state := store.Load()
	state.Transaction, state.Phase = tx, "applying"
	validator, err := protovalidate.New(protovalidate.WithMessages(&agentv1.AgentUpdateHelperState{}), protovalidate.WithDisableLazy())
	if err != nil {
		t.Fatal(err)
	}
	e := &Engine{store: store, validator: validator}
	if err := e.recordHelperState(state, helper); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = journal.OpenUpdates(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	})
	e = &Engine{store: store, validator: validator}
	state = store.Load()
	e.recordStatus(state)
	if !proto.Equal(e.Status().GetNativeDiagnostic(), want) {
		t.Fatal("executor restart lost durable failure")
	}
	if err := writeHelperState(directory, "installing", helper, nil); err != nil {
		t.Fatal(err)
	}
	if err := journal.ReadUpdateRecord(directory, "helper.pb", helper); err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(helper.GetNativeDiagnostic(), want) {
		t.Fatal("reboot recovery cleared prior native failure")
	}
	if err := e.recordHelperState(state, helper); err != nil {
		t.Fatal(err)
	}
	if err := writeHelperState(directory, "installed", helper, nil); err != nil {
		t.Fatal(err)
	}
	if err := journal.ReadUpdateRecord(directory, "helper.pb", helper); err != nil {
		t.Fatal(err)
	}
	if helper.GetNativeDiagnostic() != nil {
		t.Fatal("verified helper checkpoint retained obsolete failure")
	}
	if err := e.recordHelperState(state, helper); err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(e.Status().GetNativeDiagnostic(), want) || e.Status().GetPhase() == "installed" {
		t.Fatal("missing helper diagnostic was treated as verified native success")
	}
	state.Phase = "rejected"
	if err := e.save(state); err != nil {
		t.Fatal(err)
	}
	e.running = true
	status := e.Status()
	if status.GetPhase() != "checking" || !proto.Equal(status.GetNativeDiagnostic(), want) {
		t.Fatal("ongoing checking erased prior failure")
	}
	status.NativeDiagnostic.ErrorLines[0] = "mutated"
	if !proto.Equal(e.Status().GetNativeDiagnostic(), want) {
		t.Fatal("status caller mutated protected native diagnostic")
	}
}

func TestNativeHelperFailureVisibleBeforeTransportReconnects(t *testing.T) {
	store, err := journal.OpenUpdates(protectedRetentionDirectory(t))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	}()
	tx := retentionFixture(t, store.Directory, "")
	directory := filepath.Join(store.Directory, tx.GetId())
	state := store.Load()
	state.Transaction, state.Phase = tx, "applying"
	if err := store.Save(state); err != nil {
		t.Fatal(err)
	}
	validator, err := protovalidate.New(protovalidate.WithMessages(&agentv1.AgentUpdateHelperState{}), protovalidate.WithDisableLazy())
	if err != nil {
		t.Fatal(err)
	}
	engine := &Engine{store: store, validator: validator}
	engine.recordStatus(store.Load())
	failure := failingNativeChild(t, "", "E: native package service startup failed\n")
	for _, phase := range []string{"recovery_required", "rejected", "installing", "installed"} {
		if err := writeHelperState(directory, phase, nil, failure); err != nil {
			t.Fatal(err)
		}
		status := engine.Status()
		if phase == "recovery_required" || phase == "rejected" {
			if status.GetPhase() != phase || !proto.Equal(status.GetNativeDiagnostic(), diagnosticForError(failure)) {
				t.Fatalf("durable helper failure hidden until transport reconnect: %v", status)
			}
			status.NativeDiagnostic.ErrorLines[0] = "mutated returned diagnostic"
			if !proto.Equal(engine.Status().GetNativeDiagnostic(), diagnosticForError(failure)) {
				t.Fatal("status caller altered durable helper failure")
			}
		} else if status.GetPhase() != "applying" || status.GetNativeDiagnostic() != nil {
			t.Fatalf("helper marker promoted without independent native verification: %v", status)
		}
		if engine.running || !engine.Busy() || !proto.Equal(store.Load(), state) {
			t.Fatal("read-only status launched recovery, released its interlock or modified authority")
		}
	}
	if err := journal.WriteUpdateRecord(directory, "helper.pb", &agentv1.AgentUpdateHelperState{Phase: "unknown"}); err != nil {
		t.Fatal(err)
	}
	status := engine.Status()
	if status.GetPhase() != "recovery_required" || status.GetReason() != "update_helper_state_unavailable" || status.GetNativeDiagnostic() != nil {
		t.Fatalf("invalid durable helper observation was trusted: %v", status)
	}
}
