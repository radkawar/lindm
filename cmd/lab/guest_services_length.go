//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"time"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/agent/serviceprovider"
	"lindm/internal/vmlab"
)

// A private sleep process exposes a valid drop-in through its argv in procfs.
// Native systemd must actually load that drop-in before refusal counts as proof.
// The source reports size zero while exposing bytes, without fabricated stat data.
func serviceProofUnreportedDefinition(ctx context.Context, provider *serviceprovider.Provider) (_ *vmlab.VMServiceStep, resultErr error) {
	const description = "Disposable native unreported definition bytes proof"
	definition := "[Unit]\nDescription=" + description + "\n"
	producer := exec.CommandContext(ctx, "/usr/bin/sleep", "infinity")
	producer.Args[0] = definition
	producer.Env = []string{"LC_ALL=C"}
	if err := producer.Start(); err != nil {
		return nil, err
	}
	defer func() {
		killErr := producer.Process.Kill()
		if errors.Is(killErr, os.ErrProcessDone) {
			killErr = nil
		}
		waitErr := producer.Wait()
		var exit *exec.ExitError
		if errors.As(waitErr, &exit) {
			if status, ok := exit.Sys().(syscall.WaitStatus); ok && status.Signaled() && status.Signal() == syscall.SIGKILL {
				waitErr = nil
			}
		}
		resultErr = errors.Join(resultErr, killErr, waitErr)
	}()
	source := "/proc/" + strconv.Itoa(producer.Process.Pid) + "/cmdline"
	stat, data, err := serviceProofAwaitDefinition(ctx, source, definition+"\x00infinity\x00")
	if err != nil {
		return nil, err
	}
	directory := serviceProofDirectory + serviceProofUnit + ".d"
	if err := os.Mkdir(directory, 0755); err != nil {
		return nil, err
	}
	path := directory + "/10-unreported.conf"
	ownedLink := false
	defer func() {
		if ownedLink {
			resultErr = errors.Join(resultErr, os.Remove(path))
		}
		resultErr = errors.Join(resultErr, os.Remove(directory))
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, reloadErr := serviceProofCommand(cleanup, "/usr/bin/systemctl", "--no-ask-password", "daemon-reload")
		resultErr = errors.Join(resultErr, reloadErr)
	}()
	if err := os.Symlink(source, path); err != nil {
		return nil, err
	}
	ownedLink = true
	if _, err := os.Stat("/sys/fs/selinux/enforce"); err == nil {
		if _, err := serviceProofCommand(ctx, "/usr/sbin/restorecon", directory, path); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if _, err := serviceProofCommand(ctx, "/usr/bin/systemctl", "--no-ask-password", "daemon-reload"); err != nil {
		return nil, err
	}
	nativeDescription, err := serviceProofCommand(ctx, "/usr/bin/systemctl", "show", "--property=Description", "--value", "--", serviceProofUnit)
	if err != nil {
		return nil, err
	}
	if string(nativeDescription) != description+"\n" {
		return nil, errors.New("native manager did not load the unreported-length drop-in")
	}
	before, err := serviceProofNative(ctx, serviceProofUnit)
	if err != nil {
		return nil, err
	}
	if before.LoadState != "loaded" || before.ActiveState != "inactive" || before.UnitFileState != "indirect" {
		return nil, fmt.Errorf("unreported length refusal requires a loaded inactive indirect service: %+v", before)
	}
	desired := &agentv1.ServiceDesiredState{Unit: serviceProofUnit, Runtime: agentv1.ServiceRuntimeState_SERVICE_RUNTIME_STATE_ACTIVE, Enablement: agentv1.ServiceEnablement_SERVICE_ENABLEMENT_UNMANAGED}
	if _, err := provider.Plan(ctx, desired); !errors.Is(err, serviceprovider.ErrConflict) {
		return nil, fmt.Errorf("unreported definition bytes must fail with conflict: %v", err)
	}
	after, err := serviceProofNative(ctx, serviceProofUnit)
	if err != nil {
		return nil, err
	}
	if *before != *after {
		return nil, errors.New("unreported definition refusal changed native state")
	}
	return &vmlab.VMServiceStep{
		Name: "unreported-bytes-rejected", Target: serviceProofUnit, Rejection: "conflict",
		NativeBefore: before, NativeAfter: after,
		UnreportedDefinition: &vmlab.VMServiceDefinitionLength{
			ReportedSize: stat.Size(), ObservedSize: int64(len(data)), NativeDescription: string(nativeDescription),
		},
	}, nil
}

// Wait for the owned producer's exact bytes before exposing its argv as a
// definition. An empty read is not readiness; a different nonempty value fails.
func serviceProofAwaitDefinition(ctx context.Context, path, expected string) (os.FileInfo, []byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		file, err := os.Open(path)
		if err != nil {
			return nil, nil, err
		}
		stat, statErr := file.Stat()
		data, readErr := io.ReadAll(io.LimitReader(file, 4096))
		if err := errors.Join(statErr, readErr, file.Close()); err != nil {
			return nil, nil, err
		}
		identity, ok := stat.Sys().(*syscall.Stat_t)
		if !ok || identity.Uid != 0 {
			return nil, nil, errors.New("native definition producer source is not root-owned")
		}
		if !stat.Mode().IsRegular() || stat.Size() != 0 || (len(data) != 0 && string(data) != expected) {
			return nil, nil, fmt.Errorf("native length fixture bytes differ: mode=%s size=%d bytes=%q", stat.Mode(), stat.Size(), data)
		}
		if string(data) == expected {
			return stat, data, nil
		}
		select {
		case <-ctx.Done():
			return nil, nil, fmt.Errorf("owned native definition producer never published argv: %w", ctx.Err())
		case <-ticker.C:
		}
	}
}
