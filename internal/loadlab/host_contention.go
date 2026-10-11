package loadlab

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"lindm/internal/agent/nativeexec"
	"lindm/internal/labexec"
)

const (
	hostSampleInterval = 10 * time.Second
	hostSampleTimeout  = 4 * time.Second
	maxHostSamples     = 8192
	maxIOStatBytes     = 64 << 10
)

type DiskIOSample struct {
	Device  string
	Metrics map[string]float64 // iostat column names; await is milliseconds, %util is percent.
}

type IOStatObservation struct {
	Status          string // sampled, unavailable, failed, truncated, or invalid
	WindowSeconds   float64
	DurationSeconds float64
	Disks           []DiskIOSample
	Output          string // Bounded, locale-C output of the exact command below.
	Error           string
}

type QEMUObservation struct {
	Count         int
	PIDs          []int
	Uninspectable int
	Error         string
}

type HostContentionSample struct {
	StartedAt  time.Time
	FinishedAt time.Time
	Generator  ProcessAffinity
	Server     ProcessAffinity
	QEMU       QEMUObservation
	IOStat     IOStatObservation
}

// HostContention describes observed coexistence, not an exclusive host or a
// durability qualification. CPU affinity does not reserve CPUs against VMs.
type HostContention struct {
	CPUs                  CPUConfig
	Availability          CPUAvailability // launcher's allowance, before generator reexec
	InitialGenerator      ProcessAffinity
	InitialServer         ProcessAffinity
	SampleIntervalSeconds float64
	IOStatCommand         []string
	IOStatAvailability    string
	Samples               []HostContentionSample
	DroppedSamples        uint64
}

type HostSamplerOptions struct {
	CPUs      CPUConfig
	ServerPID func() int // Must be safe to call concurrently with fixture restart.
	Interval  time.Duration
}

type hostSamplerDependencies struct {
	affinity *AffinityController
	readDir  func(string) ([]os.DirEntry, error)
	readFile func(string) ([]byte, error)
	readlink func(string) (string, error)
	lookPath func(string) (string, error)
	run      func(context.Context, string, []string, io.Writer, io.Writer) error
	environ  func() []string
	now      func() time.Time
}

type HostSampler struct {
	options HostSamplerOptions
	deps    hostSamplerDependencies
	iostat  string
	mu      sync.Mutex
	result  HostContention
	cancel  context.CancelFunc
	done    chan struct{}
	closed  bool
}

func NewHostSampler(options HostSamplerOptions) (*HostSampler, error) {
	return newHostSampler(options, hostSamplerDependencies{})
}

func newHostSampler(options HostSamplerOptions, deps hostSamplerDependencies) (*HostSampler, error) {
	if options.ServerPID == nil {
		return nil, errors.New("host sampler requires a server PID accessor")
	}
	if options.Interval == 0 {
		options.Interval = hostSampleInterval
	}
	if options.Interval < 5*time.Second || options.Interval > time.Minute {
		return nil, errors.New("host sampling interval must be between 5 seconds and 1 minute")
	}
	if deps.affinity == nil {
		deps.affinity = NewAffinityController(AffinityDependencies{})
	}
	if deps.readDir == nil {
		deps.readDir = os.ReadDir
	}
	if deps.readFile == nil {
		deps.readFile = os.ReadFile
	}
	if deps.readlink == nil {
		deps.readlink = os.Readlink
	}
	if deps.lookPath == nil {
		deps.lookPath = exec.LookPath
	}
	if deps.run == nil {
		deps.run = runIOStat
	}
	if deps.environ == nil {
		deps.environ = os.Environ
	}
	if deps.now == nil {
		deps.now = time.Now
	}
	available, err := deps.affinity.GetCPUAvailability()
	if err != nil {
		return nil, err
	}
	marker, err := readAffinityMarker(deps.environ())
	if err != nil {
		return nil, err
	}
	if marker != nil {
		if marker.Config != options.CPUs {
			return nil, errors.New("host sampler CPU configuration differs from generator reexec")
		}
		available.AllowedCPUs = marker.AllowedCPUs
	}
	if err := ValidateCPUConfig(options.CPUs, available); err != nil {
		return nil, err
	}
	generator := deps.affinity.GetProcessAffinity(os.Getpid(), options.CPUs.GeneratorCPUs)
	server := deps.affinity.GetProcessAffinity(options.ServerPID(), options.CPUs.ServerCPUs)
	for _, role := range []struct {
		name      string
		requested string
		effective ProcessAffinity
	}{{"generator", options.CPUs.GeneratorCPUs, generator}, {"server", options.CPUs.ServerCPUs, server}} {
		if role.requested != "" && (role.effective.Error != "" || !role.effective.MatchesRequested) {
			return nil, fmt.Errorf("%s affinity does not match configured CPUs: %+v", role.name, role.effective)
		}
	}
	iostat, lookupErr := deps.lookPath("iostat")
	availability := "available"
	if lookupErr != nil {
		availability = "unavailable: iostat was not found; no disk utilization or await measurements"
	}
	return &HostSampler{options: options, deps: deps, iostat: iostat, result: HostContention{
		CPUs: options.CPUs, Availability: available, InitialGenerator: generator, InitialServer: server,
		SampleIntervalSeconds: options.Interval.Seconds(), IOStatCommand: []string{"iostat", "-dx", "1", "2"},
		IOStatAvailability: availability,
	}}, nil
}

// Start begins immediately, without blocking the workload on iostat's one-second
// sample window. The owner must Close before tearing down the fixture, then take
// Snapshot to retain the final observation. Parent cancellation also stops it.
func (s *HostSampler) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cancel != nil || s.closed {
		return errors.New("host sampler cannot be started twice or after close")
	}
	ctx, s.cancel = context.WithCancel(ctx)
	s.done = make(chan struct{})
	go s.loop(ctx)
	return nil
}

func (s *HostSampler) loop(ctx context.Context) {
	defer close(s.done)
	ticker := time.NewTicker(s.options.Interval)
	defer ticker.Stop()
	for {
		if ctx.Err() != nil {
			return
		}
		sample := s.sample(ctx)
		s.mu.Lock()
		if len(s.result.Samples) < maxHostSamples {
			s.result.Samples = append(s.result.Samples, sample)
		} else {
			s.result.DroppedSamples++
		}
		s.mu.Unlock()
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (s *HostSampler) sample(ctx context.Context) HostContentionSample {
	ctx, cancel := context.WithTimeout(ctx, hostSampleTimeout)
	defer cancel()
	sample := HostContentionSample{StartedAt: s.deps.now()}
	sample.Generator = s.deps.affinity.GetProcessAffinity(os.Getpid(), s.options.CPUs.GeneratorCPUs)
	sample.Server = s.deps.affinity.GetProcessAffinity(s.options.ServerPID(), s.options.CPUs.ServerCPUs)
	sample.QEMU = s.countQEMU(ctx)
	sample.IOStat = s.sampleIOStat(ctx)
	sample.FinishedAt = s.deps.now()
	return sample
}

// Close is idempotent and waits for the bounded command to be reaped. It never
// leaves a background sampler or iostat child behind.
func (s *HostSampler) Close() {
	s.mu.Lock()
	s.closed = true
	cancel, done := s.cancel, s.done
	s.mu.Unlock()
	if cancel != nil {
		cancel()
		<-done
	}
}

// Snapshot copies the outer slice; completed sample values and their nested
// collections are immutable. Callers must treat the returned evidence as read-only.
func (s *HostSampler) Snapshot() HostContention {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := s.result
	result.Samples = append([]HostContentionSample(nil), result.Samples...)
	return result
}

func runIOStat(ctx context.Context, binary string, args []string, stdout, stderr io.Writer) error {
	// iostat needs no application environment, especially no fixture credentials.
	return labexec.Run(ctx, labexec.Command{Path: binary, Args: args, Env: []string{"LC_ALL=C", "LANG=C", "PATH=/usr/bin:/bin"}, Stdout: stdout, Stderr: stderr})
}

func (s *HostSampler) sampleIOStat(ctx context.Context) IOStatObservation {
	if s.iostat == "" {
		return IOStatObservation{Status: "unavailable", Error: "iostat was not found; disk utilization and await were not measured"}
	}
	start := s.deps.now()
	stdout, stderr := nativeexec.NewBuffer(maxIOStatBytes), nativeexec.NewBuffer(maxIOStatBytes)
	err := s.deps.run(ctx, s.iostat, []string{"-dx", "1", "2"}, stdout, stderr)
	result := IOStatObservation{WindowSeconds: 1, DurationSeconds: s.deps.now().Sub(start).Seconds(), Output: stdout.String()}
	if err != nil {
		result.Status = "failed"
		result.Error = fmt.Sprintf("iostat: %v; %s", err, strings.TrimSpace(stderr.String()))
		return result
	}
	if stdout.Truncated() || stderr.Truncated() {
		result.Status, result.Error = "truncated", "iostat output exceeded the per-stream 64 KiB limit"
		return result
	}
	result.Disks, err = parseIOStat(result.Output)
	if err != nil {
		result.Status, result.Error = "invalid", err.Error()
		return result
	}
	result.Status = "sampled"
	return result
}

// parseIOStat deliberately discards the first (since-boot) report. Only the
// second report represents the requested one-second under-load sample window.
func parseIOStat(output string) ([]DiskIOSample, error) {
	var headers []string
	var disks []DiskIOSample
	reports := 0
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			headers = nil
			continue
		}
		if strings.TrimSuffix(fields[0], ":") == "Device" {
			reports++
			headers = fields[1:]
			disks = nil
			continue
		}
		if len(headers) == 0 {
			continue
		}
		if len(fields) != len(headers)+1 {
			return nil, errors.New("iostat device row does not match its header")
		}
		device := DiskIOSample{Device: fields[0], Metrics: make(map[string]float64, len(headers))}
		for i, header := range headers {
			value, err := strconv.ParseFloat(fields[i+1], 64)
			if err != nil || math.IsNaN(value) || math.IsInf(value, 0) || value < 0 {
				return nil, fmt.Errorf("invalid iostat metric %s for device %s", header, device.Device)
			}
			device.Metrics[header] = value
		}
		if _, ok := device.Metrics["%util"]; !ok {
			return nil, errors.New("iostat report has no %util measurement")
		}
		_, readAwait := device.Metrics["r_await"]
		_, writeAwait := device.Metrics["w_await"]
		_, await := device.Metrics["await"]
		if !await && (!readAwait || !writeAwait) {
			return nil, errors.New("iostat report has no read/write await measurements")
		}
		disks = append(disks, device)
	}
	if reports != 2 || len(disks) == 0 {
		return nil, errors.New("iostat did not return both a since-boot report and a nonempty one-second disk report")
	}
	return disks, nil
}

func qemuProcessName(name string) bool {
	name = filepath.Base(strings.TrimSuffix(strings.TrimSpace(name), " (deleted)"))
	return name == "qemu" || name == "qemu-kvm" || name == "kvm" || strings.HasPrefix(name, "qemu-system-")
}

func (s *HostSampler) countQEMU(ctx context.Context) QEMUObservation {
	var result QEMUObservation
	entries, err := s.deps.readDir("/proc")
	if err != nil {
		result.Error = fmt.Sprintf("enumerate QEMU processes: %v", err)
		return result
	}
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			result.Error = err.Error()
			break
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 {
			continue
		}
		directory := filepath.Join("/proc", entry.Name())
		executable, exeErr := s.deps.readlink(filepath.Join(directory, "exe"))
		matched := exeErr == nil && qemuProcessName(executable)
		if !matched {
			comm, commErr := s.deps.readFile(filepath.Join(directory, "comm"))
			if commErr == nil {
				matched = qemuProcessName(string(comm))
			} else if exeErr != nil && !errors.Is(commErr, os.ErrNotExist) {
				result.Uninspectable++
			}
		}
		if matched {
			result.PIDs = append(result.PIDs, pid)
			result.Count++
		}
	}
	return result
}
