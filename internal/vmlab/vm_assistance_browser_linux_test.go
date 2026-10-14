// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"lindm/internal/labexec"
)

func assistanceProtocolBrowser(t *testing.T, wire string) *assistanceBrowser {
	t.Helper()
	stdin, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	b := &assistanceBrowser{stdin: stdin, replies: make(chan assistanceBrowserReply, 1), done: make(chan struct{})}
	go b.read(strings.NewReader(wire))
	t.Cleanup(func() {
		for range b.replies {
		}
		<-b.done
		_ = stdin.Close()
	})
	return b
}

func TestAssistanceBrowserRetainsPreCommandFailureAfterBrokenPipe(t *testing.T) {
	b := assistanceProtocolBrowser(t, `{"id":0,"startupStage":"module_load"}`+"\n"+
		`{"id":0,"ok":false,"error":{"code":"module_not_found","errorType":"Error","stage":"module_load"}}`+"\n")
	if err := b.stdin.Close(); err != nil {
		t.Fatal(err)
	}
	err := b.call(t.Context(), "start", nil, nil, time.Second)
	if err == nil || !strings.Contains(err.Error(), "module_not_found") || !strings.Contains(err.Error(), "start/module_load") || !errors.Is(err, os.ErrClosed) {
		t.Fatalf("lost pre-command failure: %v", err)
	}
	if strings.Contains(err.Error(), "out of order") {
		t.Fatalf("bootstrap failure misclassified as protocol ordering: %v", err)
	}
}

func TestAssistanceBrowserStartupStagesDoNotReplaceSuccessfulReply(t *testing.T) {
	b := assistanceProtocolBrowser(t, `{"id":0,"startupStage":"module_load"}`+"\n"+
		`{"id":0,"startupStage":"configuration"}`+"\n"+
		`{"id":0,"startupStage":"chromium_launch"}`+"\n"+
		`{"id":0,"startupStage":"browser_setup"}`+"\n"+
		`{"id":0,"startupStage":"navigation"}`+"\n"+
		`{"id":0,"startupStage":"authenticator"}`+"\n"+
		`{"id":0,"startupStage":"enrollment"}`+"\n"+
		`{"id":0,"startupStage":"sign_in"}`+"\n"+
		`{"id":1,"ok":true,"result":{"version":"observed-build"}}`+"\n")
	var got struct {
		Version string `json:"version"`
	}
	if err := b.call(t.Context(), "start", nil, &got, time.Second); err != nil {
		t.Fatal(err)
	}
	if got.Version != "observed-build" {
		t.Fatalf("lost successful reply: %+v", got)
	}
}

func TestAssistanceBrowserStartupStageStreamIsBoundedAndNonsecret(t *testing.T) {
	for _, wire := range []string{
		`{"id":0,"startupStage":"private_password_cookie"}` + "\n",
		`{"id":0,"startupStage":"module_load"}` + "\n" + `{"id":0,"startupStage":"module_load"}` + "\n",
		`{"id":0,"startupStage":"configuration","error":"private_password_cookie"}` + "\n",
	} {
		b := assistanceProtocolBrowser(t, wire)
		err := b.call(t.Context(), "start", nil, nil, time.Second)
		if err == nil || err.Error() != "browser runner wrote an invalid startup stage" {
			t.Fatalf("unsafe or unbounded startup stream accepted: %v", err)
		}
	}
	b := assistanceProtocolBrowser(t, strings.Repeat("private_password_cookie", maxAssistanceBrowserReply)+"\n")
	err := b.call(t.Context(), "start", nil, nil, time.Second)
	if err == nil || !strings.Contains(err.Error(), "token too long") || strings.Contains(err.Error(), "private_password_cookie") {
		t.Fatalf("oversized diagnostic was not safely bounded: %v", err)
	}
}

func TestAssistanceBrowserEOFIsNotSuccessfulProcessExit(t *testing.T) {
	b := assistanceProtocolBrowser(t, `{"id":0,"startupStage":"chromium_launch"}`+"\n")
	err := b.call(t.Context(), "start", nil, nil, time.Second)
	if err == nil || !strings.Contains(err.Error(), "closed replies during start/chromium_launch") || strings.Contains(err.Error(), "<nil>") {
		t.Fatalf("EOF misreported: %v", err)
	}
}

func TestAssistanceBrowserCloseRetainsActualExitAfterEOF(t *testing.T) {
	for _, tc := range []struct {
		name        string
		termination string
		exitCode    int
	}{
		{"nonzero", "exit 7", 7},
		{"signal", "kill -KILL $$", -1},
		{"zero_without_reply", "exit 0", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assistanceBrowserObservedExit(t, tc.termination, tc.exitCode)
		})
	}
}

func assistanceBrowserObservedExit(t *testing.T, termination string, wantExit int) {
	t.Helper()
	childStdin, stdin, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = childStdin.Close(); _ = stdin.Close() }()
	stdout, childStdout, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = stdout.Close(); _ = childStdout.Close() }()
	process, err := labexec.Start(t.Context(), labexec.Command{
		Path: "sh",
		// Close stdout before receiving the parent's graceful-close request,
		// then terminate. EOF itself must never become a successful startup.
		Args:  []string{"-c", `IFS= read -r start; printf '%s\n' '{"id":0,"startupStage":"module_load"}'; exec 1>&-; IFS= read -r close; ` + termination},
		Stdin: childStdin, Stdout: childStdout,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = process.Close() }()
	if err := errors.Join(childStdin.Close(), childStdout.Close()); err != nil {
		t.Fatal(err)
	}
	b := &assistanceBrowser{process: process, stdin: stdin, stdout: stdout, replies: make(chan assistanceBrowserReply, 1), done: make(chan struct{})}
	go b.read(stdout)
	err = b.call(t.Context(), "start", nil, nil, 5*time.Second)
	if err == nil || !strings.Contains(err.Error(), "start/module_load") {
		t.Fatalf("lost startup failure: %v", err)
	}
	var exit *exec.ExitError
	if wantExit == 0 {
		if errors.As(err, &exit) {
			t.Fatalf("invented nonzero exit: %v", err)
		}
	} else if !errors.As(err, &exit) || exit.ExitCode() != wantExit {
		t.Fatalf("lost actual process outcome: %v", err)
	}
	if err := b.Close(); err != nil {
		t.Fatalf("repeat close: %v", err)
	}
}

func TestAssistanceBrowserExitObservationIsBoundedAndDoesNotReap(t *testing.T) {
	childStdin, stdin, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = childStdin.Close(); _ = stdin.Close() }()
	process, err := labexec.Start(t.Context(), labexec.Command{Path: "sh", Args: []string{"-c", "IFS= read -r release; exit 9"}, Stdin: childStdin})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = process.Close() }()
	if err := childStdin.Close(); err != nil {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if err := waitAssistanceBrowserExit(cancelled, process.Pid()); !errors.Is(err, context.Canceled) {
		t.Fatalf("live leader observation was not bounded: %v", err)
	}
	if _, err := stdin.Write([]byte("release\n")); err != nil {
		t.Fatal(err)
	}
	ctx, stop := context.WithTimeout(t.Context(), 5*time.Second)
	defer stop()
	if err := waitAssistanceBrowserExit(ctx, process.Pid()); err != nil {
		t.Fatal(err)
	}
	// Close can still reap the leader and signal its unrecycled process group.
	var exit *exec.ExitError
	if err := process.Close(); !errors.As(err, &exit) || exit.ExitCode() != 9 {
		t.Fatalf("observation consumed or changed the process outcome: %v", err)
	}
}
