// SPDX-License-Identifier: Apache-2.0

package loadlab

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"lindm/internal/labexec"
)

const affinityEnvironment = "LINDM_LOAD_CPU_REEXEC"

// affinityCleanupGrace covers the child's independently bounded cleanup:
// database (3m), dedicated PostgreSQL and loop storage (3m), owner session (15s),
// and server shutdown (20s). Killing sooner can orphan owned storage resources.
const affinityCleanupGrace = 7 * time.Minute

// CPUConfig isolates the three capacity roles from each other, not from other
// host workloads. Empty fields leave that role unpinned.
type CPUConfig struct {
	GeneratorCPUs string
	ServerCPUs    string
	PostgresCPUs  string
}

type CPUAvailability struct {
	OnlineCPUs  string
	AllowedCPUs string
}

// ProcessAffinity records every observed thread, rather than only the Go
// process's initial thread. CPULists contains the distinct effective masks.
type ProcessAffinity struct {
	PID              int
	Threads          int
	CPULists         []string
	MatchesRequested bool
	Error            string
}

// ParseCPUSet accepts Linux list syntax, including inclusive ranges. Duplicate
// CPUs and CPU IDs beyond Linux's supported 8192-CPU bound are rejected.
func ParseCPUSet(value string) ([]int, error) {
	if value == "" {
		return nil, errors.New("CPU list is empty")
	}
	seen := make(map[int]bool)
	for _, part := range strings.Split(value, ",") {
		ends := strings.Split(part, "-")
		if len(ends) > 2 {
			return nil, fmt.Errorf("invalid CPU list %q", value)
		}
		bounds := [2]int{}
		for i, end := range ends {
			if end == "" || strings.IndexFunc(end, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
				return nil, fmt.Errorf("invalid CPU list %q", value)
			}
			n, err := strconv.ParseUint(end, 10, 13)
			if err != nil {
				return nil, fmt.Errorf("CPU ID outside 0..8191 in %q", value)
			}
			bounds[i] = int(n)
		}
		if len(ends) == 1 {
			bounds[1] = bounds[0]
		}
		if bounds[1] < bounds[0] {
			return nil, fmt.Errorf("descending CPU range in %q", value)
		}
		for cpu := bounds[0]; cpu <= bounds[1]; cpu++ {
			if seen[cpu] {
				return nil, fmt.Errorf("duplicate CPU %d in %q", cpu, value)
			}
			seen[cpu] = true
		}
	}
	cpus := make([]int, 0, len(seen))
	for cpu := range seen {
		cpus = append(cpus, cpu)
	}
	sort.Ints(cpus)
	return cpus, nil
}

func canonicalCPUSet(cpus []int) string {
	var result strings.Builder
	for i := 0; i < len(cpus); i++ {
		if i != 0 {
			result.WriteByte(',')
		}
		result.WriteString(strconv.Itoa(cpus[i]))
		end := i
		for end+1 < len(cpus) && cpus[end+1] == cpus[end]+1 {
			end++
		}
		if end != i {
			result.WriteByte('-')
			result.WriteString(strconv.Itoa(cpus[end]))
			i = end
		}
	}
	return result.String()
}

// ValidateCPUConfig rejects unavailable CPUs and overlap between configured
// roles. AllowedCPUs must be captured before narrowing the generator affinity.
func ValidateCPUConfig(config CPUConfig, available CPUAvailability) error {
	online, err := ParseCPUSet(available.OnlineCPUs)
	if err != nil {
		return fmt.Errorf("online CPUs: %w", err)
	}
	allowed, err := ParseCPUSet(available.AllowedCPUs)
	if err != nil {
		return fmt.Errorf("allowed CPUs: %w", err)
	}
	owners := make(map[int]string)
	for _, role := range []struct{ name, cpus string }{{"generator", config.GeneratorCPUs}, {"server", config.ServerCPUs}, {"postgres", config.PostgresCPUs}} {
		if role.cpus == "" {
			continue
		}
		cpus, err := ParseCPUSet(role.cpus)
		if err != nil {
			return fmt.Errorf("%s CPUs: %w", role.name, err)
		}
		for _, cpu := range cpus {
			if i := sort.SearchInts(online, cpu); i == len(online) || online[i] != cpu {
				return fmt.Errorf("%s CPU %d is offline", role.name, cpu)
			}
			if i := sort.SearchInts(allowed, cpu); i == len(allowed) || allowed[i] != cpu {
				return fmt.Errorf("%s CPU %d is outside the launcher's allowed CPUs", role.name, cpu)
			}
			if previous := owners[cpu]; previous != "" {
				return fmt.Errorf("%s and %s overlap on CPU %d", previous, role.name, cpu)
			}
			owners[cpu] = role.name
		}
	}
	return nil
}

// AffinityDependencies permits deterministic inspection and launch tests without
// changing the test runner's affinity. Nil functions use the real host.
type AffinityDependencies struct {
	ReadFile   func(string) ([]byte, error)
	ReadDir    func(string) ([]os.DirEntry, error)
	LookPath   func(string) (string, error)
	Executable func() (string, error)
	Run        func(context.Context, string, []string, []string, io.Writer, io.Writer) error
}

type AffinityController struct {
	deps AffinityDependencies
}

func NewAffinityController(deps AffinityDependencies) *AffinityController {
	if deps.ReadFile == nil {
		deps.ReadFile = os.ReadFile
	}
	if deps.ReadDir == nil {
		deps.ReadDir = os.ReadDir
	}
	if deps.LookPath == nil {
		deps.LookPath = exec.LookPath
	}
	if deps.Executable == nil {
		deps.Executable = os.Executable
	}
	if deps.Run == nil {
		deps.Run = runAffinityCommand
	}
	return &AffinityController{deps: deps}
}

// affinityCommand cancels by TERMing the child's process group so it can run
// its owned cleanup; survivors are killed once the leader exits or after
// affinityCleanupGrace, so no descendant server is orphaned.
func affinityCommand(binary string, args, environment []string, stdout, stderr io.Writer) labexec.Command {
	return labexec.Command{Path: binary, Args: args, Env: environment, Stdin: os.Stdin, Stdout: stdout, Stderr: stderr, Interrupt: syscall.SIGTERM, Grace: affinityCleanupGrace}
}

func runAffinityCommand(ctx context.Context, binary string, args, environment []string, stdout, stderr io.Writer) error {
	return labexec.Run(ctx, affinityCommand(binary, args, environment, stdout, stderr))
}

func statusCPUList(data []byte) (string, error) {
	for _, line := range strings.Split(string(data), "\n") {
		if value, ok := strings.CutPrefix(line, "Cpus_allowed_list:"); ok {
			cpus, err := ParseCPUSet(strings.TrimSpace(value))
			if err != nil {
				return "", err
			}
			return canonicalCPUSet(cpus), nil
		}
	}
	return "", errors.New("process status has no Cpus_allowed_list")
}

func GetCPUAvailability() (CPUAvailability, error) {
	return NewAffinityController(AffinityDependencies{}).GetCPUAvailability()
}

func (c *AffinityController) GetCPUAvailability() (CPUAvailability, error) {
	var available CPUAvailability
	if runtime.GOOS != "linux" {
		return available, errors.New("CPU affinity requires Linux")
	}
	online, err := c.deps.ReadFile("/sys/devices/system/cpu/online")
	if err != nil {
		return available, fmt.Errorf("read online CPUs: %w", err)
	}
	cpus, err := ParseCPUSet(strings.TrimSpace(string(online)))
	if err != nil {
		return available, err
	}
	available.OnlineCPUs = canonicalCPUSet(cpus)
	status, err := c.deps.ReadFile("/proc/self/status")
	if err != nil {
		return available, fmt.Errorf("read allowed CPUs: %w", err)
	}
	available.AllowedCPUs, err = statusCPUList(status)
	return available, err
}

func GetProcessAffinity(pid int, requested string) ProcessAffinity {
	return NewAffinityController(AffinityDependencies{}).GetProcessAffinity(pid, requested)
}

func (c *AffinityController) GetProcessAffinity(pid int, requested string) ProcessAffinity {
	result := ProcessAffinity{PID: pid}
	if pid <= 0 {
		result.Error = "process is not running"
		return result
	}
	want := ""
	if requested != "" {
		cpus, err := ParseCPUSet(requested)
		if err != nil {
			result.Error = err.Error()
			return result
		}
		want = canonicalCPUSet(cpus)
	}
	directory := fmt.Sprintf("/proc/%d/task", pid)
	entries, err := c.deps.ReadDir(directory)
	if err != nil {
		result.Error = fmt.Sprintf("read process threads: %v", err)
		return result
	}
	masks := make(map[string]bool)
	for _, entry := range entries {
		if _, err := strconv.Atoi(entry.Name()); err != nil {
			continue
		}
		data, err := c.deps.ReadFile(filepath.Join(directory, entry.Name(), "status"))
		if errors.Is(err, os.ErrNotExist) {
			continue // A thread may exit between directory and status reads.
		}
		if err != nil {
			result.Error = fmt.Sprintf("read thread affinity: %v", err)
			return result
		}
		mask, err := statusCPUList(data)
		if err != nil {
			result.Error = err.Error()
			return result
		}
		masks[mask] = true
		result.Threads++
	}
	for mask := range masks {
		result.CPULists = append(result.CPULists, mask)
	}
	sort.Strings(result.CPULists)
	if result.Threads == 0 {
		result.Error = "no live threads observed"
	}
	result.MatchesRequested = result.Threads > 0 && want != "" && len(masks) == 1 && masks[want]
	return result
}

type affinityMarker struct {
	Version     int
	Config      CPUConfig
	AllowedCPUs string
}

func readAffinityMarker(environment []string) (*affinityMarker, error) {
	var marker *affinityMarker
	for _, entry := range environment {
		value, ok := strings.CutPrefix(entry, affinityEnvironment+"=")
		if !ok {
			continue
		}
		if marker != nil {
			return nil, errors.New("duplicate generator affinity reexec marker")
		}
		marker = &affinityMarker{}
		if err := json.Unmarshal([]byte(value), marker); err != nil || marker.Version != 1 {
			return nil, errors.New("invalid generator affinity reexec marker")
		}
	}
	return marker, nil
}

// ReexecWithGeneratorCPUs belongs at the lab command boundary, before opening a
// fixture or starting workload goroutines. taskset sets the single pre-exec
// thread's mask; the new Go runtime and all its future threads inherit it. The
// server uses its separate pre-exec taskset hook, even after fixture restarts.
// A true return means the child already ran the command: do not run it again.
func ReexecWithGeneratorCPUs(ctx context.Context, config CPUConfig, stdout, stderr io.Writer) (bool, error) {
	return NewAffinityController(AffinityDependencies{}).Reexec(ctx, config, os.Args[1:], os.Environ(), stdout, stderr)
}

func (c *AffinityController) Reexec(ctx context.Context, config CPUConfig, args, environment []string, stdout, stderr io.Writer) (bool, error) {
	marker, err := readAffinityMarker(environment)
	if err != nil {
		return false, err
	}
	if config == (CPUConfig{}) && marker == nil {
		return false, nil
	}
	available, err := c.GetCPUAvailability()
	if err != nil {
		return false, err
	}
	if marker != nil {
		if marker.Config != config || config.GeneratorCPUs == "" {
			return false, errors.New("generator affinity reexec configuration mismatch")
		}
		available.AllowedCPUs = marker.AllowedCPUs
	}
	if err := ValidateCPUConfig(config, available); err != nil {
		return false, err
	}
	if marker != nil {
		effective := c.GetProcessAffinity(os.Getpid(), config.GeneratorCPUs)
		if effective.Error != "" || !effective.MatchesRequested {
			return false, fmt.Errorf("generator reexec did not pin every thread: %+v", effective)
		}
		return false, nil
	}
	if config.GeneratorCPUs == "" {
		return false, nil
	}
	taskset, err := c.deps.LookPath("taskset")
	if err != nil {
		return false, fmt.Errorf("generator CPU affinity requires taskset: %w", err)
	}
	binary, err := c.deps.Executable()
	if err != nil {
		return false, err
	}
	encoded, err := json.Marshal(affinityMarker{Version: 1, Config: config, AllowedCPUs: available.AllowedCPUs})
	if err != nil {
		return false, err
	}
	childEnvironment := append(append([]string(nil), environment...), affinityEnvironment+"="+string(encoded))
	childArgs := append([]string{"--cpu-list", config.GeneratorCPUs, binary}, args...)
	return true, c.deps.Run(ctx, taskset, childArgs, childEnvironment, stdout, stderr)
}
