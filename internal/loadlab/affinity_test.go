package loadlab

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

func TestParseCPUSet(t *testing.T) {
	for _, test := range []struct {
		input string
		want  []int
	}{{"0", []int{0}}, {"4-6,0,2", []int{0, 2, 4, 5, 6}}, {"8191", []int{8191}}} {
		got, err := ParseCPUSet(test.input)
		if err != nil || !reflect.DeepEqual(got, test.want) {
			t.Fatalf("ParseCPUSet(%q) = %v, %v; want %v", test.input, got, err, test.want)
		}
		roundTrip, err := ParseCPUSet(canonicalCPUSet(got))
		if err != nil || !reflect.DeepEqual(roundTrip, got) {
			t.Fatalf("canonical CPU list changed its set: %v, %v", roundTrip, err)
		}
	}
	for _, value := range []string{"", "-1", "1-", "2-1", "1,,2", "1-2-3", "1,1", "0-2,2-4", "8192", "999999999999999999999", "+1", "1:2", "1 2", " 1"} {
		if _, err := ParseCPUSet(value); err == nil {
			t.Errorf("accepted invalid CPU list %q", value)
		}
	}
}

func TestValidateCPUConfig(t *testing.T) {
	available := CPUAvailability{OnlineCPUs: "0-23", AllowedCPUs: "0-19"}
	for _, test := range []struct {
		name   string
		config CPUConfig
		valid  bool
	}{
		{"defaults", CPUConfig{}, true},
		{"isolated", CPUConfig{"0-3", "4-11", "12-19"}, true},
		{"generator-server overlap", CPUConfig{"0-3", "3-7", "12-19"}, false},
		{"generator-postgres overlap", CPUConfig{"0-3", "4-11", "1,12"}, false},
		{"server-postgres overlap", CPUConfig{"0-3", "4-11", "11-19"}, false},
		{"not allowed", CPUConfig{"0-3", "4-11", "20"}, false},
		{"offline", CPUConfig{"0-3", "4-11", "24"}, false},
		{"huge range", CPUConfig{"0-99999999", "", ""}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := ValidateCPUConfig(test.config, available); (err == nil) != test.valid {
				t.Fatalf("validation = %v; valid=%t", err, test.valid)
			}
		})
	}
}

func fixtureAffinity(t *testing.T, threadCPUs ...string) *AffinityController {
	t.Helper()
	files := fstest.MapFS{}
	for i, cpus := range threadCPUs {
		files[string(rune('1'+i))+"/status"] = &fstest.MapFile{Data: []byte("Name:\tlab\nCpus_allowed_list:\t" + cpus + "\n")}
	}
	return NewAffinityController(AffinityDependencies{
		ReadDir: func(string) ([]os.DirEntry, error) { return files.ReadDir(".") },
		ReadFile: func(path string) ([]byte, error) {
			switch path {
			case "/sys/devices/system/cpu/online":
				return []byte("0-23\n"), nil
			case "/proc/self/status":
				return []byte("Cpus_allowed_list:\t0-23\n"), nil
			}
			_, suffix, ok := strings.Cut(path, "/task/")
			if !ok {
				return nil, os.ErrNotExist
			}
			return files.ReadFile(suffix)
		},
	})
}

func TestProcessAffinityInspectsAllThreads(t *testing.T) {
	for _, test := range []struct {
		threads []string
		matches bool
	}{{[]string{"0-3", "0,1,2,3"}, true}, {[]string{"0-3", "0-23"}, false}, {nil, false}} {
		result := fixtureAffinity(t, test.threads...).GetProcessAffinity(42, "0-3")
		if result.MatchesRequested != test.matches || result.Threads != len(test.threads) {
			t.Fatalf("effective affinity = %+v", result)
		}
	}
}

func TestGeneratorReexecPreservesCommandAndDoesNotLoop(t *testing.T) {
	controller := fixtureAffinity(t, "0-3", "0-3")
	config := CPUConfig{"0-3", "4-11", "12-19"}
	controller.deps.LookPath = func(name string) (string, error) {
		if name != "taskset" {
			t.Fatalf("unexpected executable %q", name)
		}
		return "/usr/bin/taskset", nil
	}
	controller.deps.Executable = func() (string, error) { return "/tmp/lab", nil }
	args := []string{"load", "-generator-cpus", "0-3", "-record", "/tmp/record with spaces"}
	var environment []string
	var stdout, stderr strings.Builder
	childFailure := errors.New("child failure")
	controller.deps.Run = func(ctx context.Context, binary string, childArgs, childEnv []string, out, errOut io.Writer) error {
		if binary != "/usr/bin/taskset" || !reflect.DeepEqual(childArgs, append([]string{"--cpu-list", "0-3", "/tmp/lab"}, args...)) {
			t.Fatalf("changed child invocation %q %q", binary, childArgs)
		}
		if out != &stdout || errOut != &stderr || ctx != context.Background() {
			t.Fatal("lost command context or output streams")
		}
		environment = childEnv
		return childFailure
	}
	reexecuted, err := controller.Reexec(context.Background(), config, args, []string{"PRESERVE=value"}, &stdout, &stderr)
	if !reexecuted || !errors.Is(err, childFailure) || len(environment) != 2 || environment[0] != "PRESERVE=value" {
		t.Fatalf("reexec = %t, %v, environment=%q", reexecuted, err, environment)
	}
	controller.deps.Run = func(context.Context, string, []string, []string, io.Writer, io.Writer) error {
		t.Fatal("recursive generator reexec")
		return nil
	}
	if reexecuted, err := controller.Reexec(context.Background(), config, args, environment, &stdout, &stderr); reexecuted || err != nil {
		t.Fatalf("child marker rejected correct all-thread pinning: %t %v", reexecuted, err)
	}
	config.ServerCPUs = "4-7"
	if _, err := controller.Reexec(context.Background(), config, args, environment, &stdout, &stderr); err == nil {
		t.Fatal("accepted mismatched marker configuration")
	}
}

func TestGeneratorReexecRejectsPartialPinningAndMalformedMarkers(t *testing.T) {
	config := CPUConfig{"0-3", "4-11", "12-19"}
	encoded, err := json.Marshal(affinityMarker{Version: 1, Config: config, AllowedCPUs: "0-23"})
	if err != nil {
		t.Fatal(err)
	}
	controller := fixtureAffinity(t, "0-3", "0-23")
	controller.deps.Run = func(context.Context, string, []string, []string, io.Writer, io.Writer) error {
		t.Fatal("must reject rather than retry reexec")
		return nil
	}
	for _, environment := range [][]string{
		{affinityEnvironment + "=" + string(encoded)},
		{affinityEnvironment + "=invalid"},
		{affinityEnvironment + "=" + string(encoded), affinityEnvironment + "=" + string(encoded)},
	} {
		if reexecuted, err := controller.Reexec(context.Background(), config, nil, environment, io.Discard, io.Discard); reexecuted || err == nil {
			t.Fatalf("accepted bad reexec state: %t %v", reexecuted, err)
		}
	}
}

func TestGeneratorDefaultDoesNotInspectOrLaunch(t *testing.T) {
	controller := NewAffinityController(AffinityDependencies{ReadFile: func(string) ([]byte, error) {
		t.Fatal("default command must not require Linux affinity inspection")
		return nil, nil
	}})
	if reexecuted, err := controller.Reexec(context.Background(), CPUConfig{}, nil, nil, io.Discard, io.Discard); reexecuted || err != nil {
		t.Fatalf("default command reexec = %t, %v", reexecuted, err)
	}
}

func TestAffinityCommandAllowsOwnedFixtureCleanup(t *testing.T) {
	cmd := newAffinityCommand(context.Background(), "/test/taskset", nil, nil, io.Discard, io.Discard)
	const ownedCleanupDeadline = 3*time.Minute + 3*time.Minute + 15*time.Second + 20*time.Second
	if cmd.WaitDelay < ownedCleanupDeadline || cmd.WaitDelay != 7*time.Minute {
		t.Fatalf("affinity cancellation grace %v does not preserve bounded owned cleanup %v", cmd.WaitDelay, ownedCleanupDeadline)
	}
	if cmd.Cancel == nil || cmd.SysProcAttr == nil || !cmd.SysProcAttr.Setpgid {
		t.Fatal("affinity command lost process-group cancellation")
	}
}
