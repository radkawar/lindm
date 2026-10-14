// SPDX-License-Identifier: Apache-2.0

package devlab

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/google/uuid"

	"lindm/internal/agent/nativeexec"
	"lindm/internal/labexec"
)

func scaleOutPython(t *testing.T) string {
	t.Helper()
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("remote custody behavior requires Python 3.11+ and Linux pidfds")
	}
	return python
}

func runScaleOutRemoteTest(t *testing.T, python, operation, directory, token string, input []byte) error {
	t.Helper()
	output := nativeexec.NewBuffer(16 << 10)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	return labexec.Run(ctx, labexec.Command{Path: python, Args: []string{"-c", scaleOutRemoteScript, operation, directory, token, ""},
		Stdin: bytes.NewReader(input), Stdout: output, Stderr: output})
}

func TestScaleOutRemoteCleanupRefusesUnrelatedLivePID(t *testing.T) {
	python := scaleOutPython(t)
	process, err := labexec.Start(context.WithoutCancel(t.Context()), labexec.Command{Path: python, Args: []string{"-c", "import time; time.sleep(60)"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := process.Close(); err != nil {
			t.Error(err)
		}
	})
	token := uuid.NewString()
	directory := filepath.Join("/tmp", "lindm-scaleout-"+token)
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(directory); err != nil {
			t.Error(err)
		}
	})
	if err := os.WriteFile(filepath.Join(directory, "owner"), []byte(token), 0600); err != nil {
		t.Fatal(err)
	}
	stat, err := os.ReadFile("/proc/" + strconv.Itoa(process.Pid()) + "/stat")
	if err != nil {
		t.Fatal(err)
	}
	fields := strings.Fields(string(stat[strings.LastIndexByte(string(stat), ')')+1:]))
	state, err := json.Marshal(map[string]any{"pid": process.Pid(), "start": fields[19]})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "state.json"), state, 0600); err != nil {
		t.Fatal(err)
	}
	if err := runScaleOutRemoteTest(t, python, "cleanup", directory, token, nil); err == nil {
		t.Fatal("cleanup accepted an unrelated executable with a matching live PID/start time")
	}
	if err := syscall.Kill(process.Pid(), 0); err != nil {
		t.Fatal("cleanup signalled an unrelated process")
	}
	if _, err := os.Stat(filepath.Join(directory, "state.json")); err != nil {
		t.Fatal("cleanup removed custody after an identity mismatch")
	}
	if err := os.Remove(filepath.Join(directory, "state.json")); err != nil {
		t.Fatal(err)
	}
	if err := runScaleOutRemoteTest(t, python, "cleanup", directory, token, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(directory); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("cleanup retained stopped owned files")
	}
	if err := syscall.Kill(process.Pid(), 0); err != nil {
		t.Fatal("owned file cleanup affected unrelated process")
	}
}

func TestScaleOutRemoteFailedStagingRemainsExactlyCleanable(t *testing.T) {
	python := scaleOutPython(t)
	token := uuid.NewString()
	directory := filepath.Join("/tmp", "lindm-scaleout-"+token)
	t.Cleanup(func() {
		if err := os.RemoveAll(directory); err != nil {
			t.Error(err)
		}
	})
	payload, err := json.Marshal(map[string]any{"binary": python, "digest": strings.Repeat("0", 64), "files": map[string][]byte{"credential": []byte("private test credential")}})
	if err != nil {
		t.Fatal(err)
	}
	if err := runScaleOutRemoteTest(t, python, "prepare", directory, token, payload); err == nil {
		t.Fatal("staged a different server binary")
	}
	if err := runScaleOutRemoteTest(t, python, "cleanup", directory, "wrong-owner", nil); err == nil {
		t.Fatal("cleanup accepted the wrong run identity")
	}
	if _, err := os.Stat(filepath.Join(directory, "credential")); err != nil {
		t.Fatal("ownership mismatch removed staged credential")
	}
	if err := runScaleOutRemoteTest(t, python, "cleanup", directory, token, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(directory); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("failed startup leaked remote custody")
	}
}
