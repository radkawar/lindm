// SPDX-License-Identifier: Apache-2.0

package devlab

import (
	"fmt"
	"os/exec"
	"runtime"

	"lindm/internal/labexec"
)

// newServerCommand applies affinity before lindmd starts its Go runtime. taskset
// execs the server in place, so the fixture still owns the actual server PID and
// its existing signal, wait and restart lifecycle. Every restart uses this hook.
func newServerCommand(binary, configPath, cpus string) (labexec.Command, error) {
	serve := labexec.Command{Path: binary, Args: []string{"serve", "-config", configPath}}
	if cpus == "" {
		return serve, nil
	}
	if runtime.GOOS != "linux" {
		return serve, fmt.Errorf("server CPU affinity requires Linux")
	}
	if err := validateLoadCPUList(cpus); err != nil {
		return serve, fmt.Errorf("server CPUs: %w", err)
	}
	taskset, err := exec.LookPath("taskset")
	if err != nil {
		return serve, fmt.Errorf("server CPU affinity requires taskset: %w", err)
	}
	return labexec.Command{Path: taskset, Args: append([]string{"--cpu-list", cpus, binary}, serve.Args...)}, nil
}

// ProcessID returns the current server PID, or zero while stopped. It is safe to
// read from a sampler while the owning goroutine restarts the fixture.
func (f *AuthorityFixture) ProcessID() int {
	return int(f.processPID.Load())
}
