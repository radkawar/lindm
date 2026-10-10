package devlab

import (
	"fmt"
	"os/exec"
	"runtime"
)

// newServerCommand applies affinity before lindmd starts its Go runtime. taskset
// execs the server in place, so the fixture still owns the actual server PID and
// its existing signal, wait and restart lifecycle. Every restart uses this hook.
func newServerCommand(binary, configPath, cpus string) (*exec.Cmd, error) {
	if cpus == "" {
		return exec.Command(binary, "serve", "-config", configPath), nil
	}
	if runtime.GOOS != "linux" {
		return nil, fmt.Errorf("server CPU affinity requires Linux")
	}
	if err := validateLoadCPUList(cpus); err != nil {
		return nil, fmt.Errorf("server CPUs: %w", err)
	}
	taskset, err := exec.LookPath("taskset")
	if err != nil {
		return nil, fmt.Errorf("server CPU affinity requires taskset: %w", err)
	}
	return exec.Command(taskset, "--cpu-list", cpus, binary, "serve", "-config", configPath), nil
}

// ProcessID returns the current server PID, or zero while stopped. It is safe to
// read from a sampler while the owning goroutine restarts the fixture.
func (f *AuthorityFixture) ProcessID() int {
	return int(f.processPID.Load())
}
