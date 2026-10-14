// SPDX-License-Identifier: Apache-2.0

package loadlab

import (
	"context"
	"errors"
	"io"
	"os"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"testing/fstest"
	"time"
)

const sampleIOStatOutput = `Linux host 6.0 x86_64

Device            r/s     w/s r_await w_await %util
nvme0n1         10.00   20.00  900.00  800.00 99.00

Device            r/s     w/s r_await w_await %util
nvme0n1         30.00   40.00    1.25    2.50 17.00
nvme1n1          0.00    2.00    0.00    0.75  3.00

`

func TestIOStatUsesMeasuredWindowNotSinceBoot(t *testing.T) {
	disks, err := parseIOStat(sampleIOStatOutput)
	if err != nil || len(disks) != 2 || disks[0].Device != "nvme0n1" || disks[0].Metrics["r_await"] != 1.25 || disks[0].Metrics["w_await"] != 2.5 || disks[0].Metrics["%util"] != 17 {
		t.Fatalf("wrong one-second disk evidence: %+v, %v", disks, err)
	}
	for _, invalid := range []string{
		"Device r_await w_await %util\nsda 1 2 3\n", // Only since-boot data.
		strings.ReplaceAll(sampleIOStatOutput, "%util", "missing"),
		strings.ReplaceAll(sampleIOStatOutput, "r_await", "missing"),
		strings.ReplaceAll(sampleIOStatOutput, "1.25", "NaN"),
		strings.ReplaceAll(sampleIOStatOutput, "1.25", "-1"),
		strings.ReplaceAll(sampleIOStatOutput, "1.25", "bad"),
	} {
		if _, err := parseIOStat(invalid); err == nil {
			t.Fatalf("accepted invalid iostat output %q", invalid)
		}
	}
}

func samplerDependencies(t *testing.T) hostSamplerDependencies {
	t.Helper()
	return hostSamplerDependencies{
		affinity: fixtureAffinity(t, "0-23", "0-23"),
		readDir:  func(string) ([]os.DirEntry, error) { return nil, nil },
		lookPath: func(string) (string, error) { return "/usr/bin/iostat", nil },
		environ:  func() []string { return nil },
		run: func(_ context.Context, binary string, args []string, stdout, _ io.Writer) error {
			if binary != "/usr/bin/iostat" || !reflect.DeepEqual(args, []string{"-dx", "1", "2"}) {
				t.Errorf("unexpected iostat invocation: %q %q", binary, args)
			}
			_, err := io.WriteString(stdout, sampleIOStatOutput)
			return err
		},
	}
}

func TestHostSamplerRecordsMissingIOStatExplicitly(t *testing.T) {
	deps := samplerDependencies(t)
	deps.lookPath = func(string) (string, error) { return "", os.ErrNotExist }
	deps.run = func(context.Context, string, []string, io.Writer, io.Writer) error {
		t.Fatal("must not run an unavailable iostat")
		return nil
	}
	sampler, err := newHostSampler(HostSamplerOptions{ServerPID: func() int { return 42 }}, deps)
	if err != nil {
		t.Fatal(err)
	}
	defer sampler.Close()
	sample := sampler.sample(context.Background())
	if sample.IOStat.Status != "unavailable" || sample.IOStat.Disks != nil || sample.IOStat.Error == "" || !strings.HasPrefix(sampler.Snapshot().IOStatAvailability, "unavailable") {
		t.Fatalf("missing iostat was hidden: %+v", sample.IOStat)
	}
}

func TestHostSamplerBoundsOutputAndHonorsDeadline(t *testing.T) {
	deps := samplerDependencies(t)
	deps.run = func(ctx context.Context, _ string, _ []string, stdout, stderr io.Writer) error {
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > hostSampleTimeout {
			t.Error("iostat command has no bounded sampling deadline")
		}
		chunk := strings.Repeat("x", maxIOStatBytes+100)
		if n, err := io.WriteString(stdout, chunk); err != nil || n != len(chunk) {
			t.Errorf("truncated writer failed to drain output: %d, %v", n, err)
		}
		_, _ = io.WriteString(stderr, chunk)
		return nil
	}
	sampler, err := newHostSampler(HostSamplerOptions{ServerPID: func() int { return 42 }}, deps)
	if err != nil {
		t.Fatal(err)
	}
	defer sampler.Close()
	result := sampler.sample(context.Background()).IOStat
	if result.Status != "truncated" || len(result.Output) != maxIOStatBytes || result.Disks != nil {
		t.Fatalf("unbounded or fabricated disk sample: %+v", result)
	}
}

func TestHostSamplerCloseCancelsAndReapsSampler(t *testing.T) {
	deps := samplerDependencies(t)
	entered := make(chan struct{})
	exited := make(chan struct{})
	deps.run = func(ctx context.Context, _ string, _ []string, _, _ io.Writer) error {
		close(entered)
		<-ctx.Done()
		close(exited)
		return ctx.Err()
	}
	sampler, err := newHostSampler(HostSamplerOptions{ServerPID: func() int { return 42 }}, deps)
	if err != nil {
		t.Fatal(err)
	}
	defer sampler.Close()
	if err := sampler.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("sampler did not start its initial window")
	}
	closed := make(chan struct{})
	go func() {
		sampler.Close()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("Close did not cancel its command")
	}
	select {
	case <-exited:
	default:
		t.Fatal("Close returned with a command still running")
	}
	result := sampler.Snapshot()
	if len(result.Samples) != 1 || result.Samples[0].IOStat.Status != "failed" || !strings.Contains(result.Samples[0].IOStat.Error, context.Canceled.Error()) {
		t.Fatalf("lost cancellation evidence: %+v", result)
	}
	if err := sampler.Start(context.Background()); err == nil {
		t.Fatal("restarted a closed sampler")
	}
}

func TestHostSamplerTracksServerPIDAcrossRestart(t *testing.T) {
	deps := samplerDependencies(t)
	var pid atomic.Int64
	pid.Store(42)
	sampler, err := newHostSampler(HostSamplerOptions{ServerPID: func() int { return int(pid.Load()) }}, deps)
	if err != nil {
		t.Fatal(err)
	}
	defer sampler.Close()
	pid.Store(0)
	stopped := sampler.sample(context.Background())
	pid.Store(43)
	restarted := sampler.sample(context.Background())
	if sampler.Snapshot().InitialServer.PID != 42 || stopped.Server.Error == "" || restarted.Server.PID != 43 || restarted.Server.Error != "" {
		t.Fatalf("server restart lost: stopped=%+v restarted=%+v", stopped.Server, restarted.Server)
	}
}

func TestQEMUCountUsesExecutableAndCommWithoutCommandLines(t *testing.T) {
	deps := samplerDependencies(t)
	files := fstest.MapFS{
		"10/comm": &fstest.MapFile{Data: []byte("qemu-system-x86\n")},
		"20/comm": &fstest.MapFile{Data: []byte("renamed-vm\n")},
		"30/comm": &fstest.MapFile{Data: []byte("qemu-img\n")},
		"40/comm": &fstest.MapFile{Data: []byte("unreadable")},
		"50/comm": &fstest.MapFile{Data: []byte("exited")},
	}
	deps.readDir = func(path string) ([]os.DirEntry, error) {
		if path != "/proc" {
			t.Fatalf("unexpected process discovery %q", path)
		}
		return files.ReadDir(".")
	}
	deps.readFile = func(path string) ([]byte, error) {
		if !strings.HasSuffix(path, "/comm") {
			t.Fatalf("read non-comm process metadata %q", path)
		}
		switch path {
		case "/proc/40/comm":
			return nil, os.ErrPermission
		case "/proc/50/comm":
			return nil, os.ErrNotExist
		}
		return files.ReadFile(strings.TrimPrefix(path, "/proc/"))
	}
	deps.readlink = func(path string) (string, error) {
		if path == "/proc/20/exe" {
			return "/usr/bin/qemu-system-aarch64 (deleted)", nil
		}
		return "", os.ErrPermission
	}
	sampler, err := newHostSampler(HostSamplerOptions{ServerPID: func() int { return 42 }}, deps)
	if err != nil {
		t.Fatal(err)
	}
	defer sampler.Close()
	result := sampler.countQEMU(context.Background())
	if result.Count != 2 || !reflect.DeepEqual(result.PIDs, []int{10, 20}) || result.Uninspectable != 1 || result.Error != "" {
		t.Fatalf("wrong QEMU contention evidence: %+v", result)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if result := sampler.countQEMU(ctx); !strings.Contains(result.Error, context.Canceled.Error()) {
		t.Fatalf("QEMU enumeration ignored cancellation: %+v", result)
	}
}

func TestHostSamplerRejectsInvalidLifecycleOptions(t *testing.T) {
	for _, options := range []HostSamplerOptions{
		{},
		{ServerPID: func() int { return 42 }, Interval: time.Millisecond},
		{ServerPID: func() int { return 42 }, Interval: 2 * time.Minute},
		{ServerPID: func() int { return 42 }, CPUs: CPUConfig{GeneratorCPUs: "0-3"}},
	} {
		if sampler, err := newHostSampler(options, samplerDependencies(t)); err == nil {
			sampler.Close()
			t.Fatalf("accepted invalid sampler options %+v", options)
		}
	}
	deps := samplerDependencies(t)
	deps.run = func(context.Context, string, []string, io.Writer, io.Writer) error {
		return errors.New("iostat failed")
	}
	sampler, err := newHostSampler(HostSamplerOptions{ServerPID: func() int { return 42 }}, deps)
	if err != nil {
		t.Fatal(err)
	}
	defer sampler.Close()
	if result := sampler.sample(context.Background()).IOStat; result.Status != "failed" || len(result.Disks) != 0 {
		t.Fatalf("command failure fabricated metrics: %+v", result)
	}
}
