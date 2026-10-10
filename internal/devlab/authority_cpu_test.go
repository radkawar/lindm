package devlab

import (
	"os/exec"
	"reflect"
	"runtime"
	"testing"
)

func TestAuthorityServerCommandKeepsUnpinnedAPI(t *testing.T) {
	cmd, err := newServerCommand("/tmp/lindmd", "/tmp/server config.json", "")
	if err != nil || cmd.Path != "/tmp/lindmd" || !reflect.DeepEqual(cmd.Args, []string{"/tmp/lindmd", "serve", "-config", "/tmp/server config.json"}) {
		t.Fatalf("default authority command changed: %+v, %v", cmd, err)
	}
}

func TestAuthorityServerCommandPinsBeforeRuntimeOnEveryLaunch(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux affinity command")
	}
	taskset, err := exec.LookPath("taskset")
	if err != nil {
		t.Skip("taskset is not installed; no subprocess is launched by this test")
	}
	for range 2 {
		cmd, err := newServerCommand("/tmp/lindmd", "/tmp/server config.json", "4-11")
		want := []string{taskset, "--cpu-list", "4-11", "/tmp/lindmd", "serve", "-config", "/tmp/server config.json"}
		if err != nil || cmd.Path != taskset || !reflect.DeepEqual(cmd.Args, want) {
			t.Fatalf("server runtime would start without taskset exec: %+v, %v", cmd, err)
		}
	}
	if _, err := newServerCommand("/tmp/lindmd", "/tmp/server.json", "4; touch /tmp/unwanted"); err == nil {
		t.Fatal("accepted invalid CPU list")
	}
}

func TestAuthorityProcessIDTracksAtomicLifecycle(t *testing.T) {
	fixture := &AuthorityFixture{}
	if fixture.ProcessID() != 0 {
		t.Fatal("new fixture has a process")
	}
	fixture.processPID.Store(42)
	if fixture.ProcessID() != 42 {
		t.Fatal("running fixture lost its server PID")
	}
	fixture.processPID.Store(0)
	if fixture.ProcessID() != 0 {
		t.Fatal("stopped fixture retained its server PID")
	}
}
