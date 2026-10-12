package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	labv1 "lindm/gen/lindm/lab/v1"
	"lindm/internal/demolab"
	"lindm/internal/labhost"
	"lindm/internal/redhatimages"
)

const (
	demoRunName  = "lindm-lab-5d6f28880123456789abcdef01234567"
	demoConsumer = "a4142e23-89ab-4cde-8f01-23456789abcd"
)

// demoRedHatState is a controller state for a desktop on dgx20 and an
// entitled server on dgx21, persisted in a fresh controller demo root.
func demoRedHatState(t *testing.T) (string, *labv1.DemoState) {
	t.Helper()
	binding := func(key, hostname, host, group string, role labv1.DemoRole) *labv1.DemoBinding {
		return &labv1.DemoBinding{
			Key: key, DemoName: "org-" + key, ManifestSha256: strings.Repeat("a", 64),
			Host: &labv1.LabHost{Name: host, Transport: "ssh", SshAlias: host, Architectures: []string{"arm64"}, Kvm: true, MaxGuests: 2, MaxVcpus: 8, MaxMemoryMib: 16384, WorkDirectory: "~/lindm-lab", Runtime: "native"},
			Device: &labv1.DemoDevice{Key: key, Hostname: hostname, Manifest: "../images/" + key + ".json", Role: role, Group: group, ProvisioningToken: key, Host: proto.String(host),
				Firmware: &labv1.DemoFirmware{Code: "/usr/share/AAVMF/AAVMF_CODE.secboot.fd", Vars: "/usr/share/AAVMF/AAVMF_VARS.ms.fd", Package: "qemu-efi-aarch64", Version: "2024.02-2ubuntu0.10", SecureBoot: proto.Bool(true)}},
		}
	}
	state := &labv1.DemoState{RecordsRedhatRegistrations: true, Bindings: []*labv1.DemoBinding{
		binding("engineering-laptop", "demo-engineering-01", "dgx20", "26d5407e-0035-5ae1-b4c9-83d105e13915", labv1.DemoRole_DEMO_ROLE_DESKTOP),
		binding("it-server", "it-infra-01", "dgx21", "ce806573-be05-59fa-9891-8b152b22efb3", labv1.DemoRole_DEMO_ROLE_SERVER),
	}}
	root := filepath.Join(t.TempDir(), "org")
	if err := openAssistanceDemoRoot(root); err != nil {
		t.Fatal(err)
	}
	if err := writeDemoState(root, state); err != nil {
		t.Fatal(err)
	}
	return root, state
}

func savedRegistration(t *testing.T, root string) *labv1.DemoRedHatRegistration {
	t.Helper()
	state, err := readDemoState(root)
	if err != nil {
		t.Fatal(err)
	}
	return state.GetBindings()[1].GetRedhatRegistration()
}

// The remote worker's registration step returns only after the controller's
// demo-state.json holds the identity: the run name before Red Hat is
// contacted, then its consumer before any further guest operation.
func TestDemoRegistrationPersistsOnControllerBeforeWorkerContinues(t *testing.T) {
	root, state := demoRedHatState(t)
	run := &demoRun{root: root, state: state}
	evidence := t.TempDir()
	marker := filepath.Join(evidence, labhost.RegistrationMarker)
	for _, step := range []*labv1.RedHatRegistrationIdentity{{RunName: demoRunName}, {RunName: demoRunName, ConsumerUuid: demoConsumer}} {
		worker := make(chan error, 1)
		go func() { worker <- publishDemoRegistration(t.Context(), evidence, step, time.Millisecond) }()
		deadline := time.Now().Add(10 * time.Second)
		var data []byte
		for {
			var err error
			if data, err = os.ReadFile(marker); err == nil {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("worker published no registration marker")
			}
			time.Sleep(time.Millisecond)
		}
		select {
		case err := <-worker:
			t.Fatalf("worker continued before the controller recorded its registration: %v", err)
		default:
		}
		// The SSH watcher records the marker, then removes it as the acknowledgement.
		if err := run.recordRegistrationMarker("it-server", data); err != nil {
			t.Fatal(err)
		}
		if saved := savedRegistration(t, root); saved.GetRunName() != step.GetRunName() || saved.GetConsumerUuid() != step.GetConsumerUuid() {
			t.Fatalf("controller state = %v, want %v", saved, step)
		}
		if err := os.Remove(marker); err != nil {
			t.Fatal(err)
		}
		if err := <-worker; err != nil {
			t.Fatal(err)
		}
	}
}

// Resume reads the recorded consumer back from the controller state: the same
// identity is accepted again, and nothing replaces or re-registers it.
func TestDemoResumeReadsRecordedConsumer(t *testing.T) {
	root, state := demoRedHatState(t)
	run := &demoRun{root: root, state: state}
	// A host without a receipt never contacted Red Hat, so a fresh run name
	// replaces an unconfirmed one before the consumer is recorded.
	for _, identity := range []*labv1.RedHatRegistrationIdentity{
		{RunName: "lindm-lab-00000000000000000000000000000001"},
		{RunName: demoRunName},
		{RunName: demoRunName, ConsumerUuid: demoConsumer},
	} {
		if err := run.recordRedHatRegistration("it-server", identity); err != nil {
			t.Fatal(err)
		}
	}
	var spec demolab.Spec
	for _, bound := range state.Bindings {
		spec.Devices = append(spec.Devices, demolab.Device{Config: proto.CloneOf(bound.Device), Manifest: &labv1.ImageManifest{Sha256: bound.ManifestSha256}})
	}
	resumed, err := bindDemoState("org", root, &spec, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := &labv1.DemoRedHatRegistration{RunName: demoRunName, ConsumerUuid: demoConsumer}
	if !proto.Equal(resumed.GetBindings()[1].GetRedhatRegistration(), want) || !resumed.GetRecordsRedhatRegistrations() {
		t.Fatalf("resumed state lost the controller record: %v", resumed)
	}
	again := &demoRun{root: root, state: resumed}
	if err := again.recordRedHatRegistration("it-server", &labv1.RedHatRegistrationIdentity{RunName: demoRunName, ConsumerUuid: demoConsumer}); err != nil {
		t.Fatalf("repeated identical record refused: %v", err)
	}
	for _, identity := range []*labv1.RedHatRegistrationIdentity{
		{RunName: "lindm-lab-00000000000000000000000000000002"},
		{RunName: demoRunName, ConsumerUuid: "11111111-1111-4111-8111-111111111111"},
		{RunName: "lindm-lab-00000000000000000000000000000002", ConsumerUuid: demoConsumer},
		{RunName: "vendor-hostname", ConsumerUuid: demoConsumer},
	} {
		if err := again.recordRedHatRegistration("it-server", identity); err == nil {
			t.Fatalf("recorded consumer replaced by %v", identity)
		}
	}
	if err := again.recordRegistrationMarker("it-server", []byte("not protobuf json")); err == nil {
		t.Fatal("malformed registration marker accepted")
	}
	if !proto.Equal(savedRegistration(t, root), want) {
		t.Fatal("refused records changed the controller state")
	}
	// The unregistered desktop cannot adopt another run's consumer either.
	pending := &demoRun{root: root, state: resumed}
	if err := pending.recordRedHatRegistration("engineering-laptop", &labv1.RedHatRegistrationIdentity{RunName: "lindm-lab-00000000000000000000000000000003"}); err != nil {
		t.Fatal(err)
	}
	if err := pending.recordRedHatRegistration("engineering-laptop", &labv1.RedHatRegistrationIdentity{RunName: demoRunName, ConsumerUuid: demoConsumer}); err == nil {
		t.Fatal("consumer recorded under another run name")
	}
	resumed.Destroying = true
	if err := writeDemoState(root, resumed); err != nil {
		t.Fatal(err)
	}
	if _, err := bindDemoState("org", root, &spec, nil); err == nil || !strings.Contains(err.Error(), "-destroy") {
		t.Fatalf("demo with pending host cleanup resumed: %v", err)
	}
}

type demoDestroyFake struct {
	unreachable map[string]bool
	devices     []string
	removals    []string
	removal     func(uuid string) (redhatimages.SystemRemoval, error)
	controller  int
}

func (f *demoDestroyFake) destroyer(root, token string, stdout *bytes.Buffer) *demoDestroy {
	return &demoDestroy{
		options: demoOptions{name: "org", repository: ".", build: ".", redhatToken: token}, root: root, stdout: stdout,
		probe: func(_ context.Context, host *labv1.LabHost) error {
			if f.unreachable[host.GetName()] {
				return fmt.Errorf("%w: %s", labhost.ErrHostUnreachable, host.GetName())
			}
			return nil
		},
		device: func(_ context.Context, bound *labv1.DemoBinding) error {
			f.devices = append(f.devices, bound.GetKey())
			return nil
		},
		removeSystem: func(_ context.Context, uuid, name string) (redhatimages.SystemRemoval, error) {
			f.removals = append(f.removals, uuid+" "+name)
			if f.removal != nil {
				return f.removal(uuid)
			}
			return redhatimages.SystemRemoval{UUID: uuid, Deleted: true, Absent: true}, nil
		},
		controller: func(context.Context) error {
			f.controller++
			return nil
		},
	}
}

// With its host unreachable, destroy removes exactly the controller-recorded
// consumer, records that, keeps the controller and reports the command that
// finishes host cleanup. An already absent consumer is a removal too.
func TestDemoDestroyUnreachableHostRemovesRecordedConsumer(t *testing.T) {
	for name, removal := range map[string]redhatimages.SystemRemoval{
		"deleted":        {UUID: demoConsumer, Deleted: true, Absent: true},
		"already-absent": {UUID: demoConsumer, Absent: true},
	} {
		t.Run(name, func(t *testing.T) {
			root, state := demoRedHatState(t)
			state.Bindings[1].RedhatRegistration = &labv1.DemoRedHatRegistration{RunName: demoRunName, ConsumerUuid: demoConsumer}
			if err := writeDemoState(root, state); err != nil {
				t.Fatal(err)
			}
			fake := &demoDestroyFake{unreachable: map[string]bool{"dgx21": true}, removal: func(string) (redhatimages.SystemRemoval, error) { return removal, nil }}
			var out bytes.Buffer
			if err := fake.destroyer(root, "/protected/redhat-offline-token", &out).run(t.Context()); err != nil {
				t.Fatal(err)
			}
			if strings.Join(fake.removals, ",") != demoConsumer+" "+demoRunName {
				t.Fatalf("removed %q, want exactly the recorded consumer", fake.removals)
			}
			if strings.Join(fake.devices, ",") != "engineering-laptop" || fake.controller != 0 {
				t.Fatalf("destroyed devices %q, controller %d", fake.devices, fake.controller)
			}
			saved, err := readDemoState(root)
			if err != nil {
				t.Fatal(err)
			}
			if !saved.GetDestroying() || !saved.GetBindings()[1].GetRedhatRegistration().GetRemoved() {
				t.Fatalf("removal not recorded on the controller: %v", saved)
			}
			for _, line := range []string{"Unregistered Red Hat system " + demoConsumer + " (" + demoRunName + ")", "Pending host cleanup: device it-server (org-it-server) on unreachable host dgx21", "is NOT fully destroyed", " demo -name org -destroy -repo ", " -redhat-token-file /protected/redhat-offline-token"} {
				if !strings.Contains(out.String(), line) {
					t.Fatalf("output lacks %q:\n%s", line, out.String())
				}
			}
			if strings.Contains(out.String(), "Destroyed organization demo") {
				t.Fatal("partial destroy claimed full destruction")
			}
			// Still unreachable: the recorded removal is not repeated.
			out.Reset()
			if err := fake.destroyer(root, "", &out).run(t.Context()); err != nil || len(fake.removals) != 1 || fake.controller != 0 {
				t.Fatalf("repeated destroy = %v, removals %q, controller %d", err, fake.removals, fake.controller)
			}
			// The host returns: its own destroy finishes, then the controller.
			fake.unreachable, fake.devices = nil, nil
			out.Reset()
			if err := fake.destroyer(root, "/protected/redhat-offline-token", &out).run(t.Context()); err != nil {
				t.Fatal(err)
			}
			if strings.Join(fake.devices, ",") != "engineering-laptop,it-server" || fake.controller != 1 || len(fake.removals) != 1 || !strings.Contains(out.String(), "Destroyed organization demo: org") {
				t.Fatalf("completed destroy: devices %q, controller %d, removals %q:\n%s", fake.devices, fake.controller, fake.removals, out.String())
			}
		})
	}
}

// Destroy never guesses a consumer the controller did not record, and a failed
// or unverified removal is a failure, not pending cleanup.
func TestDemoDestroyRefusesUnrecordedConsumer(t *testing.T) {
	for name, test := range map[string]struct {
		registration *labv1.DemoRedHatRegistration
		legacy       bool
		token        string
		removal      func(string) (redhatimages.SystemRemoval, error)
		want         string
	}{
		"unconfirmed-run": {registration: &labv1.DemoRedHatRegistration{RunName: demoRunName}, token: "/token", want: demoRunName},
		"legacy-state":    {legacy: true, token: "/token", want: "receipt on dgx21"},
		"missing-token":   {registration: &labv1.DemoRedHatRegistration{RunName: demoRunName, ConsumerUuid: demoConsumer}, want: "-redhat-token-file"},
		"removal-failed": {registration: &labv1.DemoRedHatRegistration{RunName: demoRunName, ConsumerUuid: demoConsumer}, token: "/token", want: "ownership changed",
			removal: func(uuid string) (redhatimages.SystemRemoval, error) {
				return redhatimages.SystemRemoval{UUID: uuid}, errors.New("redhatimages: system ownership changed before removal")
			}},
		"absence-unverified": {registration: &labv1.DemoRedHatRegistration{RunName: demoRunName, ConsumerUuid: demoConsumer}, token: "/token", want: "not observed absent",
			removal: func(uuid string) (redhatimages.SystemRemoval, error) {
				return redhatimages.SystemRemoval{UUID: uuid, Deleted: true}, nil
			}},
	} {
		t.Run(name, func(t *testing.T) {
			root, state := demoRedHatState(t)
			state.RecordsRedhatRegistrations = !test.legacy
			state.Bindings[1].RedhatRegistration = test.registration
			if err := writeDemoState(root, state); err != nil {
				t.Fatal(err)
			}
			fake := &demoDestroyFake{unreachable: map[string]bool{"dgx21": true}, removal: test.removal}
			var out bytes.Buffer
			err := fake.destroyer(root, test.token, &out).run(t.Context())
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("destroy = %v, want refusal naming %q", err, test.want)
			}
			if test.removal == nil && len(fake.removals) != 0 {
				t.Fatalf("guessed consumer removal %q", fake.removals)
			}
			saved, readErr := readDemoState(root)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if saved.GetBindings()[1].GetRedhatRegistration().GetRemoved() || !saved.GetDestroying() || fake.controller != 0 {
				t.Fatalf("refused destroy recorded removal or destroyed the controller: %v", saved)
			}
			if !strings.Contains(out.String(), "Pending host cleanup: device it-server") {
				t.Fatalf("pending host cleanup not reported:\n%s", out.String())
			}
		})
	}
	// An unregistered device on an unreachable host leaves only host cleanup.
	root, _ := demoRedHatState(t)
	fake := &demoDestroyFake{unreachable: map[string]bool{"dgx20": true, "dgx21": true}}
	var out bytes.Buffer
	if err := fake.destroyer(root, "", &out).run(t.Context()); err != nil || len(fake.removals) != 0 || len(fake.devices) != 0 {
		t.Fatalf("unregistered unreachable devices = %v, removals %q, devices %q", err, fake.removals, fake.devices)
	}
	// A reachable host's failed destroy is genuine and keeps the controller.
	root, _ = demoRedHatState(t)
	failing := &demoDestroyFake{}
	destroy := failing.destroyer(root, "", &out)
	destroy.device = func(context.Context, *labv1.DemoBinding) error { return errors.New("active lifecycle lock") }
	if err := destroy.run(t.Context()); err == nil || failing.controller != 0 {
		t.Fatalf("failed host destroy = %v, controller %d", err, failing.controller)
	}
}

// The marker carries only the public identity in protobuf JSON.
func TestDemoRegistrationMarkerIsPublicIdentity(t *testing.T) {
	evidence := t.TempDir()
	identity := &labv1.RedHatRegistrationIdentity{RunName: demoRunName, ConsumerUuid: demoConsumer}
	ctx, cancel := context.WithCancel(t.Context())
	worker := make(chan error, 1)
	go func() { worker <- publishDemoRegistration(ctx, evidence, identity, time.Millisecond) }()
	deadline := time.Now().Add(10 * time.Second)
	for {
		data, err := os.ReadFile(filepath.Join(evidence, labhost.RegistrationMarker))
		if err == nil {
			decoded := new(labv1.RedHatRegistrationIdentity)
			if err := protojson.Unmarshal(data, decoded); err != nil || !proto.Equal(decoded, identity) {
				t.Fatalf("marker %q, %v", data, err)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no registration marker")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	if err := <-worker; err == nil {
		t.Fatal("stopped worker reported an acknowledged registration")
	}
}
